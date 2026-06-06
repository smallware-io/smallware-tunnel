//! Forwarding utilities for tunnel connections.
//!
//! This module provides functions to forward tunnel traffic to local services,
//! which is the most common use case for tunnel clients.
//!
//! # Overview
//!
//! - [`forward_tunnel`]: Forward tunnel traffic to any `AsyncRead + AsyncWrite` stream
//! - [`forward_tunnel_tcp`]: Convenience function to forward to a TCP socket address

use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use procmachines::{
    CyclicBufProvider, IoError, IoReader, IoWriter, ReaderIoReader, WriterIoWriter,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::tunnel_protocol::TunnelConnection;
use crate::{connect_to_error, TunnelError};

type StandardBufProvider = CyclicBufProvider<2, fn() -> BytesMut>;

pub struct TunnelIoTermination<W, R>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    writer: WriterIoWriter<W>,
    reader: ReaderIoReader<R, StandardBufProvider>,
}

impl<W, R> TunnelIoTermination<W, R>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    pub fn new(writer: W, reader: R) -> Self {
        let buf_provider = StandardBufProvider::new(|| BytesMut::with_capacity(32768));
        Self {
            writer: WriterIoWriter::new(writer),
            reader: ReaderIoReader::new(reader, buf_provider),
        }
    }
}

impl<W, R> IoReader for TunnelIoTermination<W, R>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    type Error = IoError;

    #[inline(always)]
    fn con_poll_read(
        &self,
        cx: &mut std::task::Context<'_>,
        max_len: usize,
    ) -> std::task::Poll<Result<Option<Bytes>, Self::Error>> {
        self.reader.con_poll_read(cx, max_len)
    }

    #[inline(always)]
    fn drop_read(&self) {
        self.reader.drop_read();
    }
}

impl<W, R> IoWriter for TunnelIoTermination<W, R>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    type Error = IoError;

    #[inline(always)]
    fn prod_poll_write(
        &self,
        cx: &mut std::task::Context<'_>,
        bytes: &mut Bytes,
    ) -> std::task::Poll<Result<usize, Self::Error>> {
        self.writer.prod_poll_write(cx, bytes)
    }

    #[inline(always)]
    fn prod_poll_flush(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.writer.prod_poll_flush(cx)
    }

    #[inline(always)]
    fn prod_poll_close(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.writer.prod_poll_close(cx)
    }
}

/// Forwards tunnel traffic to a local TCP socket address.
///
/// This is a convenience function that connects to the given address and then
/// calls [`forward_tunnel`] to tunnel a connection to it.
///
/// # Arguments
///
/// * `conn` - The tunnel connection for sending data to the remote client
/// * `addr` - The local socket address to forward traffic to
///
/// # Returns
///
/// Returns statistics about the forwarding session, or an error if the
/// connection to the local address failed.
pub async fn forward_tunnel_tcp(
    conn: Arc<dyn TunnelConnection>,
    addr: SocketAddr,
) -> Result<(), TunnelError> {
    tracing::info!("Forwarding to {}", &addr);
    let local_stream = TcpStream::connect(addr).await.map_err(|e| {
        let ret = TunnelError::IoError(format!("Failed to connect to {}: {}", addr, e).into());
        connect_to_error(conn.clone(), e.into());
        ret
    })?;
    let (local_read, local_write) = local_stream.into_split();
    forward_tunnel(conn, local_write, local_read).await
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
/// * `conn` - The tunnel connection for sending data to the remote client
/// * `local_read` - The read half of the local connection
/// * `local_write` - The write half of the local connection
pub async fn forward_tunnel<R, W>(
    conn: Arc<dyn TunnelConnection>,
    local_write: W,
    local_read: R,
) -> Result<(), TunnelError>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let termination = Arc::new(Mutex::new(TunnelIoTermination::new(
        local_write,
        local_read,
    )));
    let t2 = termination.clone();
    conn.connect_io(termination, t2)
}
