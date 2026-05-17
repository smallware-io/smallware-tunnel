//! `5get` test: open one HTTPS keep-alive connection and issue 5 sequential
//! `GET /<random>` requests, verifying each response.

use anyhow::Result;
use rand::Rng;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::helpers::{build_tls_connector, connect_with_retry, https_get, make_server_name};

pub async fn run(domain: &str, trust_ca: Option<&PathBuf>) -> Result<()> {
    let connector = build_tls_connector(trust_ca)?;
    let server_name = make_server_name(domain)?;

    let mut tls = connect_with_retry(domain, &connector, &server_name).await?;
    info!("HTTPS keep-alive connection established to {domain}");

    let mut rng = rand::thread_rng();
    let mut spill: Vec<u8> = Vec::with_capacity(32 * 1024);

    for i in 1..=5 {
        // Random size in [1024, 200_000]; large enough to cross multiple
        // tunnel/TLS records, small enough to keep the test fast.
        let len: usize = rng.gen_range(1024..=200_000);
        https_get(&mut tls, domain, len, &mut spill, &format!("{i}/5")).await?;
    }

    let _ = tls.shutdown().await;
    Ok(())
}
