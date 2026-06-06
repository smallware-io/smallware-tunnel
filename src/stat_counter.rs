use std::sync::{Arc, LazyLock};

use derivative::Derivative;

pub const STAT_COUNT_ACCEPTS_WAITING: &str = "acc_waiting";
pub const STAT_COUNT_CONNECTIONS: &str = "connections";
pub const STAT_COUNT_BYTES_UP: &str = "up_bytes";
pub const STAT_COUNT_BYTES_DOWN: &str = "down_bytes";

pub trait StatCounter: Send + Sync {
    fn stat_count(&self, stat: &'static str, delta: i32);
    fn stat_level(&self, stat: &'static str, value: i32);
}

struct NullStatCounter {}

impl StatCounter for NullStatCounter {
    fn stat_count(&self, _stat: &'static str, _delta: i32) {}
    fn stat_level(&self, _stat: &'static str, _value: i32) {}
}

static NOOP_COUNTER: LazyLock<Arc<NullStatCounter>> =
    LazyLock::new(|| Arc::new(NullStatCounter {}));

pub fn noop_stat_counter() -> Arc<dyn StatCounter> {
    NOOP_COUNTER.clone() as Arc<dyn StatCounter>
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct ScopeStat {
    #[derivative(Debug = "ignore")]
    counter: Arc<dyn StatCounter>,
    stat: &'static str,
}

impl Clone for ScopeStat {
    fn clone(&self) -> Self {
        ScopeStat::new(&self.counter, self.stat)
    }
}

impl ScopeStat {
    pub fn new(counter: &Arc<dyn StatCounter>, stat: &'static str) -> Self {
        counter.stat_count(stat, 1);
        Self {
            counter: counter.clone(),
            stat,
        }
    }
}

impl Drop for ScopeStat {
    fn drop(&mut self) {
        self.counter.stat_count(self.stat, -1);
    }
}
