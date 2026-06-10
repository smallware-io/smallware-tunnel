//! Shared client-side helpers used by every test: TLS connector setup,
//! HTTPS connect with retry, and a single keep-alive `GET /<len>` exchange
//! that verifies the response.

use anyhow::{Context, Result, anyhow, bail};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// Build a TLS connector that trusts the system roots, plus an optional
/// extra CA in PEM format.
pub fn build_tls_connector(trust_ca: Option<&PathBuf>) -> Result<tokio_rustls::TlsConnector> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(ca_path) = trust_ca {
        let ca_file = std::fs::File::open(ca_path)
            .with_context(|| format!("failed to open CA file {ca_path:?}"))?;
        let mut reader = std::io::BufReader::new(ca_file);
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.context("failed to parse CA cert")?;
            root_store
                .add(cert)
                .context("failed to add CA cert to root store")?;
        }
    }
    let tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(tls_cfg)))
}

pub fn make_server_name(domain: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    rustls::pki_types::ServerName::try_from(domain.to_string())
        .map_err(|e| anyhow!("invalid domain {domain}: {e}"))
}

/// Connect to `<domain>:443`, retrying briefly while the tunnel is still
/// being registered upstream.
pub async fn connect_with_retry(
    domain: &str,
    connector: &tokio_rustls::TlsConnector,
    server_name: &rustls::pki_types::ServerName<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match connect_tls(domain, connector, server_name.clone()).await {
            Ok(conn) => return Ok(conn),
            Err(e) if attempt < 10 => {
                debug!(?attempt, error = %e, "tunnel not ready yet, retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.context("failed to establish HTTPS to tunnel domain")),
        }
    }
}

async fn connect_tls(
    domain: &str,
    connector: &tokio_rustls::TlsConnector,
    server_name: rustls::pki_types::ServerName<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect((domain, 443))
        .await
        .with_context(|| format!("TCP connect to {domain}:443 failed"))?;
    tcp.set_nodelay(true).ok();
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;
    Ok(tls)
}

/// Send `GET /<len>` on an existing TLS keep-alive connection and verify
/// the response: 200 status, `Content-Length: <len>`, and exactly that many
/// body bytes. `spill` carries any bytes already pulled off the socket
/// across calls (for keep-alive pipelining safety).
pub async fn https_get(
    tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    domain: &str,
    len: usize,
    spill: &mut Vec<u8>,
    label: &str,
) -> Result<()> {
    let req = format!("GET /{len} HTTP/1.1\r\nHost: {domain}\r\nConnection: keep-alive\r\n\r\n");
    tls.write_all(req.as_bytes()).await?;
    tls.flush().await?;

    let header_end = loop {
        if let Some(pos) = find_subslice(spill, b"\r\n\r\n") {
            break pos + 4;
        }
        let mut tmp = [0u8; 4096];
        let n = tls.read(&mut tmp).await?;
        if n == 0 {
            bail!("connection closed before headers on request {label}");
        }
        spill.extend_from_slice(&tmp[..n]);
        if spill.len() > 64 * 1024 {
            bail!("response headers too large on request {label}");
        }
    };

    let header_str = std::str::from_utf8(&spill[..header_end])
        .map_err(|_| anyhow!("non-UTF8 response headers"))?;
    let status_line = header_str.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        bail!("request {label} (/{len}) got non-200 status: {status_line:?}");
    }
    let cl = parse_content_length(header_str)
        .with_context(|| format!("missing Content-Length on request {label}"))?;
    if cl != len {
        bail!("request {label} (/{len}) returned Content-Length {cl}, expected {len}");
    }

    let already = spill.len() - header_end;
    let body_have = already.min(cl);
    let mut total_body = body_have;
    while total_body < cl {
        let mut tmp = [0u8; 16 * 1024];
        let want = (cl - total_body).min(tmp.len());
        let n = tls.read(&mut tmp[..want]).await?;
        if n == 0 {
            bail!("connection closed mid-body on request {label}: got {total_body} of {cl} bytes");
        }
        total_body += n;
    }

    let consumed = header_end + body_have;
    spill.drain(..consumed);

    info!("request {label}: GET /{len} → {cl} bytes ✓");
    Ok(())
}

pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().ok();
            }
        }
    }
    None
}
