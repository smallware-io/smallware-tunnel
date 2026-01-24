//! Forwarding utilities for tunnel connections.
//!
//! This module provides functions to forward tunnel traffic to local services,
//! which is the most common use case for tunnel clients.
//!
//! # Overview
//!
//! - [`forward_tunnel`]: Forward tunnel traffic to any `AsyncRead + AsyncWrite` stream
//! - [`forward_tunnel_tcp`]: Convenience function to forward to a TCP socket address
//!
//! # Example
//!
//! ```rust,no_run
//! use smallware_tunnel::{TunnelConfig, TunnelListener, forward_tunnel_tcp};
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Key format: <keyid>.<secret>
//! let config = TunnelConfig::new("mykey.secret123", "www-abc-xyz.t00.smallware.io")?;
//! let listener = TunnelListener::new(config)?;
//! let local_addr: SocketAddr = "127.0.0.1:8080".parse()?;
//!
//! loop {
//!     let (sink, stream, _client_info) = listener.accept().await?;
//!     tokio::spawn(async move {
//!         if let Err(e) = forward_tunnel_tcp(sink, stream, local_addr).await {
//!             eprintln!("Forward error: {}", e);
//!         }
//!     });
//! }
//! # }
//! ```

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{TunnelError, TunnelSink, TunnelStream};

/// Statistics from a completed tunnel forwarding session.
#[derive(Debug, Clone, Copy)]
pub struct ForwardStats {
    /// Bytes received from the tunnel and sent to the local service
    pub bytes_downloaded: u64,
    /// Bytes received from the local service and sent to the tunnel
    pub bytes_uploaded: u64,
}

/// Forwards tunnel traffic to a local TCP socket address.
///
/// This is a convenience function that connects to the given address and then
/// calls [`forward_tunnel`] to handle the bidirectional data transfer.
///
/// # Arguments
///
/// * `sink` - The tunnel sink for sending data to the remote client
/// * `stream` - The tunnel stream for receiving data from the remote client
/// * `addr` - The local socket address to forward traffic to
///
/// # Returns
///
/// Returns statistics about the forwarding session, or an error if the
/// connection to the local address failed.
///
/// # Example
///
/// ```rust,no_run
/// use smallware_tunnel::{TunnelSink, TunnelStream, forward_tunnel_tcp};
/// use std::net::SocketAddr;
///
/// async fn handle(sink: TunnelSink, stream: TunnelStream) {
///     let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
///     match forward_tunnel_tcp(sink, stream, addr).await {
///         Ok(stats) => println!("Transferred {} down, {} up", stats.bytes_downloaded, stats.bytes_uploaded),
///         Err(e) => eprintln!("Error: {}", e),
///     }
/// }
/// ```
pub async fn forward_tunnel_tcp(
    sink: TunnelSink,
    stream: TunnelStream,
    addr: SocketAddr,
) -> Result<ForwardStats, TunnelError> {
    tracing::info!("Forwarding to {}", &addr);
    let local_stream = TcpStream::connect(addr).await.map_err(|e| {
        TunnelError::IoError(format!("Failed to connect to {}: {}", addr, e).into())
    })?;

    let (local_read, local_write) = local_stream.into_split();
    forward_tunnel(sink, stream, local_write, local_read).await
}

/// Forwards tunnel traffic to any async read/write stream.
///
/// This function handles bidirectional data transfer between a tunnel connection
/// and a local service. It spawns two tasks internally:
/// - One to forward data from the tunnel to the local service (download)
/// - One to forward data from the local service to the tunnel (upload)
///
/// The function returns when both directions have completed (either successfully
/// or due to an error/EOF).
///
/// # Arguments
///
/// * `sink` - The tunnel sink for sending data to the remote client
/// * `stream` - The tunnel stream for receiving data from the remote client
/// * `local_read` - The read half of the local connection
/// * `local_write` - The write half of the local connection
///
/// # Returns
///
/// Returns statistics about the forwarding session.
///
/// # Example
///
/// ```rust,no_run
/// use smallware_tunnel::{TunnelSink, TunnelStream, forward_tunnel};
/// use tokio::net::TcpStream;
///
/// async fn handle(sink: TunnelSink, stream: TunnelStream, local: TcpStream) {
///     let (read, write) = local.into_split();
///     let stats = forward_tunnel(sink, stream, write, read).await.unwrap();
///     println!("Downloaded: {}, Uploaded: {}", stats.bytes_downloaded, stats.bytes_uploaded);
/// }
/// ```
pub async fn forward_tunnel<R, W>(
    sink: TunnelSink,
    stream: TunnelStream,
    local_write: W,
    local_read: R,
) -> Result<ForwardStats, TunnelError>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    // Spawn tasks for bidirectional proxy
    // tunnel -> local (download: data from remote client to local service)
    let download_handle = tokio::spawn(proxy_tunnel_to_local(stream, local_write));

    // local -> tunnel (upload: data from local service to remote client)
    let upload_handle = tokio::spawn(proxy_local_to_tunnel(local_read, sink));

    // Wait for both to complete
    let (download_result, upload_result) = tokio::join!(download_handle, upload_handle);

    let bytes_downloaded = download_result
        .map_err(|e| TunnelError::IoError(format!("Download task panicked: {}", e).into()))?;
    let bytes_uploaded = upload_result
        .map_err(|e| TunnelError::IoError(format!("Upload task panicked: {}", e).into()))?;

    Ok(ForwardStats {
        bytes_downloaded,
        bytes_uploaded,
    })
}

/// Proxies data from the tunnel to the local service.
async fn proxy_tunnel_to_local<W>(mut tunnel: TunnelStream, mut local: W) -> u64
where
    W: AsyncWrite + Unpin,
{
    let mut total_bytes = 0u64;

    while let Some(data) = tunnel.next().await {
        if data.is_empty() {
            // EOF from tunnel
            tracing::debug!("EOF from tunnel");
            break;
        }
        total_bytes += data.len() as u64;
        if let Err(e) = local.write_all(&data).await {
            tracing::warn!(error = %e, "Error writing to local service");
            break;
        }
        if let Err(e) = local.flush().await {
            tracing::warn!(error = %e, "Error flushing to local service");
            break;
        }
    }

    // Shutdown the write half to signal EOF to local service
    let _ = local.shutdown().await;

    total_bytes
}

/// Proxies data from the local service to the tunnel.
async fn proxy_local_to_tunnel<R>(mut local: R, mut tunnel: TunnelSink) -> u64
where
    R: AsyncRead + Unpin,
{
    let mut total_bytes = 0u64;
    let mut buf = vec![0u8; 16 * 1024];

    loop {
        match local.read(&mut buf).await {
            Ok(0) => {
                // EOF from local
                tracing::info!("EOF from local service");
                break;
            }
            Ok(n) => {
                total_bytes += n as u64;
                if let Err(e) = tunnel.send(Bytes::copy_from_slice(&buf[..n])).await {
                    tracing::warn!(error = %e, "Error writing to tunnel");
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Error reading from local service");
                break;
            }
        }
    }

    // Close the sink to signal EOF
    let _ = tunnel.close().await;

    total_bytes
}
