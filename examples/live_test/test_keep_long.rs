//! `keep_long` test: identical to `keep_recycle` but with a 7-second wait
//! between the server-initiated close and the second GET. The longer wait
//! is intended to exceed the tunnel's recycle window, so the second
//! request must be served by a freshly established link.

use anyhow::Result;
use std::path::PathBuf;
use std::time::Duration;

use crate::test_keep_recycle;

pub async fn run(domain: &str, trust_ca: Option<&PathBuf>) -> Result<()> {
    test_keep_recycle::run_with_wait(domain, trust_ca, Duration::from_secs(7)).await
}
