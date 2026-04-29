//! `recycle` test: do one GET, abruptly drop the connection (RST, no
//! TLS/TCP shutdown), wait 2 seconds, then open a fresh connection and do
//! another GET. Exercises the tunnel's connection-recycling path.
//!
//! The same scenario with a longer wait is exposed as `no_recycle`, which
//! is expected to fall outside the recycle window so the tunnel must
//! establish a fresh link rather than reuse a recycled one.

use anyhow::Result;
use rand::Rng;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::helpers::{build_tls_connector, connect_with_retry, https_get, make_server_name};

pub async fn run(domain: &str, trust_ca: Option<&PathBuf>) -> Result<()> {
    run_with_wait(domain, trust_ca, Duration::from_secs(2)).await
}

pub async fn run_with_wait(domain: &str, trust_ca: Option<&PathBuf>, wait: Duration) -> Result<()> {
    let connector = build_tls_connector(trust_ca)?;
    let server_name = make_server_name(domain)?;

    let mut rng = rand::thread_rng();

    // First connection: do one GET, then abruptly drop without TLS or TCP
    // shutdown — the underlying TCP gets SO_LINGER=0 so close() sends RST.
    let mut tls = connect_with_retry(domain, &connector, &server_name).await?;
    info!("First HTTPS connection established to {domain}");

    let mut spill: Vec<u8> = Vec::with_capacity(32 * 1024);
    let len1: usize = rng.gen_range(1024..=100_000);
    https_get(&mut tls, domain, len1, &mut spill, "first").await?;

    // Force RST-on-close, then drop without calling shutdown.
    {
        let (tcp, _) = tls.get_ref();
        let _ = tcp.set_linger(Some(Duration::from_secs(0)));
    }
    drop(tls);
    info!(
        wait_s = wait.as_secs(),
        "Connection dropped abruptly; sleeping before reconnecting"
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
