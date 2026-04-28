//! `keep_recycle` test: do one GET, then sit on the keep-alive connection
//! until the server closes it from idle timeout. After that, wait a short
//! delay and open a fresh connection for a second GET. Exercises the
//! tunnel's connection-recycling path when the upstream side closed first.
//!
//! The same scenario with a longer wait is exposed as `keep_long`, which
//! is expected to fall outside the recycle window.

use anyhow::{bail, Result};
use rand::Rng;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

use crate::helpers::{build_tls_connector, connect_with_retry, https_get, make_server_name};

pub async fn run(domain: &str, trust_ca: Option<&PathBuf>) -> Result<()> {
    run_with_wait(domain, trust_ca, Duration::from_secs(2)).await
}

pub async fn run_with_wait(
    domain: &str,
    trust_ca: Option<&PathBuf>,
    wait: Duration,
) -> Result<()> {
    let connector = build_tls_connector(trust_ca)?;
    let server_name = make_server_name(domain)?;

    let mut rng = rand::thread_rng();

    // First connection: do one GET, then wait on the keep-alive socket for
    // the server's idle timeout to close it (~10s).
    let mut tls = connect_with_retry(domain, &connector, &server_name).await?;
    info!("First HTTPS connection established to {domain}");

    let mut spill: Vec<u8> = Vec::with_capacity(32 * 1024);
    let len1: usize = rng.gen_range(1024..=100_000);
    https_get(&mut tls, domain, len1, &mut spill, "first").await?;

    info!("Waiting for server to close keep-alive connection");
    let close_wait = tokio::time::timeout(Duration::from_secs(20), async {
        let mut tmp = [0u8; 1024];
        loop {
            let n = tls.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    match close_wait {
        Ok(Ok(())) => info!("Server closed keep-alive connection cleanly"),
        Ok(Err(e)) => bail!("error waiting for server close: {e}"),
        Err(_) => bail!("timed out waiting for server to close keep-alive connection"),
    }
    let _ = tls.shutdown().await;
    drop(tls);

    info!(
        wait_s = wait.as_secs(),
        "Server-closed; sleeping before reconnecting"
    );
    tokio::time::sleep(wait).await;

    // Second connection: should succeed regardless of whether the upstream
    // recycled the prior link or had to spin up a new one.
    let mut tls2 = connect_with_retry(domain, &connector, &server_name).await?;
    info!("Second HTTPS connection established to {domain}");

    let mut spill2: Vec<u8> = Vec::with_capacity(32 * 1024);
    let len2: usize = rng.gen_range(1024..=100_000);
    https_get(&mut tls2, domain, len2, &mut spill2, "second").await?;

    let _ = tls2.shutdown().await;
    Ok(())
}
