use std::sync::atomic::AtomicU64;

use chrono::Utc;
use tokio_tungstenite::tungstenite::Utf8Bytes;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TraceId(Utf8Bytes);

impl From<String> for TraceId {
    fn from(value: String) -> Self {
        Self(value.into())
    }
}
impl From<&str> for TraceId {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl std::fmt::Display for TraceId {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

static NEXT_INC: AtomicU64 = AtomicU64::new(1);

/// Generates the next unique request ID.
pub(crate) fn next_trace_id() -> TraceId {
    let mut inc = NEXT_INC.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    while inc < ((1 as u64) << 63) {
        let mut ts = Utc::now().timestamp_millis() as u64;
        ts = ts.wrapping_mul(0x3ab287cefcf83) % 0x00ff_ffff_ffff_ffff;
        ts |= (1 as u64) << 63;
        let _ = NEXT_INC.compare_exchange(
            inc + 1,
            ts,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        );
        inc = NEXT_INC.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    let string = format!("{:x}", inc & 0x00ff_ffff_ffff_ffff);
    string.into()
}
