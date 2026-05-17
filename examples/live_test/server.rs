//! Tiny HTTP/1.1 test server.
//!
//! Handles `GET /nnnn` requests by replying with `Content-Length: nnnn` and
//! exactly that many `'A'` bytes of body. Honors keep-alive so the same TCP
//! connection can serve many requests in sequence.

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

const REQUEST_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

use crate::helpers::find_subslice;

pub async fn run_test_http_server(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((sock, peer)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_test_http_conn(sock).await {
                        debug!(?peer, error = %e, "test server connection ended");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "test server accept error");
                break;
            }
        }
    }
}

async fn handle_test_http_conn(mut sock: TcpStream) -> Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);

    loop {
        // Read until end-of-headers (CRLF CRLF).
        let header_end = loop {
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            let mut tmp = [0u8; 1024];
            let n = match tokio::time::timeout(REQUEST_IDLE_TIMEOUT, sock.read(&mut tmp)).await {
                Ok(res) => res?,
                Err(_) => {
                    // Idle too long waiting for a request; close the connection.
                    return Ok(());
                }
            };
            if n == 0 {
                // Clean keep-alive close.
                return Ok(());
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 64 * 1024 {
                bail!("request headers too large");
            }
        };

        let header_str = std::str::from_utf8(&buf[..header_end])
            .map_err(|_| anyhow!("non-UTF8 request headers"))?;
        let first_line = header_str.lines().next().unwrap_or("");
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");

        if method != "GET" {
            let resp =
                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            sock.write_all(resp).await?;
            return Ok(());
        }

        // Path is /nnnn — parse the number.
        let n_str = path.trim_start_matches('/');
        let n: usize = match n_str.parse() {
            Ok(v) => v,
            Err(_) => {
                let body = b"bad path: expected /<number>";
                let resp = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                sock.write_all(resp.as_bytes()).await?;
                sock.write_all(body).await?;
                return Ok(());
            }
        };

        let resp_header =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nConnection: keep-alive\r\n\r\n");
        sock.write_all(resp_header.as_bytes()).await?;

        // Body: just `n` 'A' bytes, written in chunks.
        let chunk_size = 16 * 1024;
        let chunk = vec![b'A'; chunk_size];
        let mut remaining = n;
        while remaining > 0 {
            let to_send = chunk.len().min(remaining);
            sock.write_all(&chunk[..to_send]).await?;
            remaining -= to_send;
        }

        // Drop the consumed request bytes; anything beyond `header_end` is
        // pipelined data (unlikely from our test client, but handle it).
        buf.drain(..header_end);
    }
}
