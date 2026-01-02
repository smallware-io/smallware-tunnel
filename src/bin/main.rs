//! Smallware Tunnel CLI
//!
//! A command-line tool for establishing tunnels from a local port to the
//! Smallware tunnel server, making local services accessible via a public URL.
//!
//! # Usage
//!
//! ```bash
//! smallware-tunnel --key KEYID.SECRET www-abc-xyz.t00.smallware.io 8080
//! ```
//!
//! This will establish a tunnel so that requests to
//! `https://www-abc-xyz.t00.smallware.io` are proxied to `localhost:8080`.
//!
//! # Options
//!
//! - `--key` or `-k`: Your API key in `<keyid>.<secret>` format (can also be set via `SMALLWARE_KEY` env var)
//! - `--server`: Custom tunnel server URL
//! - `-v` or `--verbose`: Enable verbose logging
//!
//! # Example
//!
//! ```bash
//! # Using command line option (key format: keyid.secret)
//! smallware-tunnel -k mykey.secret123 www-abc-xyz.t00.smallware.io 3000
//!
//! # Using environment variable
//! export SMALLWARE_KEY=mykey.secret123
//! smallware-tunnel www-abc-xyz.t00.smallware.io 3000
//!
//! # With custom options
//! smallware-tunnel -k mykey.secret123 -v www-abc-xyz.t00.smallware.io 8080
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use smallware_tunnel::{forward_tunnel_tcp, TunnelConfig, TunnelError, TunnelListener};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{error, info, warn, Level};

/// Smallware Tunnel CLI - Expose local services through secure tunnels
#[derive(Parser, Debug)]
#[command(name = "smallware-tunnel")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The API key for authentication in `<keyid>.<secret>` format.
    ///
    /// The key ID may contain `.` characters, but the secret cannot.
    /// Can also be provided via the SMALLWARE_KEY environment variable.
    #[arg(short, long, env = "SMALLWARE_KEY")]
    key: String,

    /// The tunnel domain to register.
    ///
    /// Format: <service>-<random>-<customer>.<shard>.smallware.io
    /// Example: www-abc-xyz.t00.smallware.io
    #[arg(value_name = "DOMAIN")]
    domain: String,

    /// The local port to forward traffic to.
    ///
    /// Traffic from the tunnel will be proxied to localhost on this port.
    /// If this is just a port number, then 127.0.0.1 is assumed.  Otherwise
    /// it must be in the form IP:PORT.
    #[arg(value_name = "PORT")]
    local_port: String,

    /// Custom tunnel server URL.
    ///
    /// Override the default server for development or testing.
    #[arg(long)]
    server: Option<String>,

    /// Path to a PEM file containing a root CA certificate to trust.
    ///
    /// When specified, this CA will be trusted in addition to the system's
    /// default root certificates. Useful for development or testing against
    /// servers using self-signed certificates.
    #[arg(long)]
    trust_ca: Option<PathBuf>,

    /// Enable verbose logging.
    ///
    /// Shows detailed debug information about connections and data transfer.
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // Initialize logging
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Build the tunnel configuration
    let mut config = TunnelConfig::new(&args.key, &args.domain)
        .context("Invalid API key format. Expected '<keyid>.<secret>'")?;

    if let Some(server_url) = args.server {
        config = config.with_server_url(server_url);
    }

    if let Some(ca_path) = args.trust_ca {
        config = config.with_trust_ca(ca_path);
    }

    let target = if args.local_port.contains(':') {
        args.local_port.clone()
    } else {
        format!("127.0.0.1:{}", args.local_port)
    };
    let local_addr: SocketAddr = target.parse().context("Invalid local port")?;

    info!(
        domain = %args.domain,
        local_port = args.local_port,
        "Starting tunnel"
    );

    // Create the tunnel listener
    let listener = TunnelListener::new(config).context("Failed to create tunnel listener")?;

    info!(
        "Tunnel active! Requests to https://{} will be forwarded to {}",
        args.domain, local_addr
    );

    // Accept and handle connections
    loop {
        match listener.accept().await {
            Ok((sink, stream)) => {
                info!("New tunnel connection");

                // Spawn a task to handle this connection
                tokio::spawn(async move {
                    match forward_tunnel_tcp(sink, stream, local_addr).await {
                        Ok(stats) => {
                            info!(
                                downloaded = stats.bytes_downloaded,
                                uploaded = stats.bytes_uploaded,
                                "Connection completed"
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, "Connection handler error");
                        }
                    }
                });
            }
            Err(TunnelError::ListenerClosed) => {
                info!("Tunnel listener closed");
                break;
            }
            Err(e) => {
                error!(error = %e, "Error accepting connection");
                break;
            }
        }
    }

    Ok(())
}
