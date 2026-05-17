//! Live end-to-end test of the tunnel.
//!
//! Takes the same arguments as the `smallware-tunnel` CLI: a key, public
//! tunnel domain, local port, and the optional `--server` / `--trust-ca` /
//! `--verbose` flags, plus `--test <NAME>` to select which test to run.
//!
//! On startup the example:
//!
//! 1. Binds a tiny HTTP/1.1 server on the local target address (see
//!    [`server`]). The server handles `GET /nnnn` by returning a body of
//!    exactly `nnnn` bytes and supports keep-alive.
//!
//! 2. Starts a tunnel listener exactly like the CLI binary, forwarding
//!    incoming tunnel connections to that local server.
//!
//! 3. Runs the selected client test against `https://<domain>`.
//!
//! 4. Tears down the tunnel and the local server and exits.

mod helpers;
mod server;
mod test_5get;
mod test_keep_long;
mod test_keep_recycle;
mod test_no_recycle;
mod test_recycle;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use smallware_tunnel::{forward_tunnel_tcp, JwtManager, TunnelConfig, TunnelError, TunnelListener};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn, Instrument, Level};

#[derive(Parser, Debug)]
#[command(name = "live_test", about = "Live end-to-end test of the tunnel")]
struct Args {
    #[arg(short, long, env = "SMALLWARE_KEY")]
    key: String,

    #[arg(value_name = "DOMAIN")]
    domain: String,

    #[arg(value_name = "PORT")]
    local_port: String,

    /// Which test to run.
    #[arg(short, long, value_enum)]
    test: Test,

    #[arg(long)]
    server: Option<String>,

    #[arg(long)]
    trust_ca: Option<PathBuf>,

    #[arg(short, long)]
    verbose: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Test {
    /// Make 5 sequential keep-alive GET /nnnn requests and verify the
    /// returned bodies match the requested length.
    #[value(name = "5get")]
    FiveGet,

    /// Do one GET, abruptly drop the connection (no graceful shutdown),
    /// wait 2 seconds, then open a fresh connection and do another GET.
    /// Exercises the tunnel's connection-recycling path.
    #[value(name = "recycle")]
    Recycle,

    /// Same as `recycle`, but waits 7 seconds before reconnecting — long
    /// enough to fall outside the tunnel's recycle window.
    #[value(name = "no_recycle")]
    NoRecycle,

    /// Do one GET, wait for the server to close the keep-alive connection
    /// from idle timeout, wait 2 seconds, then open a fresh connection and
    /// do another GET. Exercises connection recycling after a
    /// server-initiated close.
    #[value(name = "keep_recycle")]
    KeepRecycle,

    /// Same as `keep_recycle`, but waits 7 seconds before reconnecting —
    /// long enough to fall outside the tunnel's recycle window.
    #[value(name = "keep_long")]
    KeepLong,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    let auth =
        JwtManager::from_access_key(&args.key).map_err(|_| anyhow!("Malformed access key"))?;
    let auth = Arc::new(auth);

    let mut config = TunnelConfig::new(args.domain.clone());
    if let Some(server_url) = args.server.clone() {
        config = config.with_server_url(server_url);
    }
    if let Some(ca_path) = args.trust_ca.clone() {
        config = config.with_trust_ca(ca_path);
    }

    let target = if args.local_port.contains(':') {
        args.local_port.clone()
    } else {
        format!("127.0.0.1:{}", args.local_port)
    };
    let local_addr: SocketAddr = target.parse().context("Invalid local port")?;

    // Bind the local HTTP test server *before* starting the tunnel so that
    // any tunnel-forwarded connection is guaranteed to find it ready.
    let http_listener = TcpListener::bind(local_addr)
        .await
        .with_context(|| format!("failed to bind local test server on {local_addr}"))?;
    info!("Local test HTTP server listening on {local_addr}");
    let http_server_task = tokio::spawn(server::run_test_http_server(http_listener));

    info!(
        domain = %args.domain,
        local_port = args.local_port,
        "Starting tunnel"
    );

    let listener = TunnelListener::new(auth, config, None);
    let tunnel_task = tokio::spawn(run_tunnel_loop(listener, local_addr));

    // Run the selected client test; bound the whole thing so a broken setup
    // can't hang.
    let client_result = tokio::time::timeout(
        Duration::from_secs(60),
        run_selected_test(args.test, &args.domain, args.trust_ca.as_ref()),
    )
    .await;

    // Tear down regardless of outcome.
    tunnel_task.abort();
    http_server_task.abort();
    let _ = tunnel_task.await;
    let _ = http_server_task.await;

    match client_result {
        Ok(Ok(())) => {
            info!("Live test PASSED");
            Ok(())
        }
        Ok(Err(e)) => {
            error!(error = %e, "Live test FAILED");
            Err(e)
        }
        Err(_) => {
            error!("Live test FAILED: timed out after 60s");
            Err(anyhow!("live test timed out"))
        }
    }
}

async fn run_selected_test(test: Test, domain: &str, trust_ca: Option<&PathBuf>) -> Result<()> {
    match test {
        Test::FiveGet => test_5get::run(domain, trust_ca).await,
        Test::Recycle => test_recycle::run(domain, trust_ca).await,
        Test::NoRecycle => test_no_recycle::run(domain, trust_ca).await,
        Test::KeepRecycle => test_keep_recycle::run(domain, trust_ca).await,
        Test::KeepLong => test_keep_long::run(domain, trust_ca).await,
    }
}

async fn run_tunnel_loop(listener: TunnelListener, local_addr: SocketAddr) {
    loop {
        match listener.accept().await {
            Ok((sink, stream, client_info)) => {
                tokio::spawn(
                    async move {
                        match forward_tunnel_tcp(sink, stream, local_addr).await {
                            Ok(stats) => {
                                debug!(
                                    downloaded = stats.bytes_downloaded,
                                    uploaded = stats.bytes_uploaded,
                                    "Tunnel connection completed"
                                );
                            }
                            Err(e) => {
                                warn!(error = %e, "Tunnel forward error");
                            }
                        }
                    }
                    .instrument(tracing::info_span!(
                        "proxy",
                        connid = %client_info.connection_id
                    )),
                );
            }
            Err(TunnelError::ListenerClosed) => {
                info!("Tunnel listener closed");
                break;
            }
            Err(e) => {
                error!(error = %e, "Error accepting tunnel connection");
                break;
            }
        }
    }
}
