use std::sync::Arc;

use parking_lot::Mutex;
use procmachines::{IoError, IoReader, IoWriter};

use crate::tunnel_protocol::TunnelConnection;

pub struct ErrorTermination {
    err: IoError,
}

impl ErrorTermination {
    pub fn new(err: IoError) -> Self {
        Self { err }
    }
}

impl IoWriter for ErrorTermination {
    type Error = IoError;

    fn prod_poll_write(
        &self,
        _cx: &mut std::task::Context<'_>,
        _bytes: &mut bytes::Bytes,
    ) -> std::task::Poll<Result<usize, Self::Error>> {
        std::task::Poll::Ready(Err(self.err))
    }

    fn prod_poll_flush(
        &self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Err(self.err))
    }

    fn prod_poll_close(
        &self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Err(self.err))
    }
}

impl IoReader for ErrorTermination {
    type Error = IoError;

    fn con_poll_read(
        &self,
        _cx: &mut std::task::Context<'_>,
        _max_len: usize,
    ) -> std::task::Poll<Result<Option<bytes::Bytes>, Self::Error>> {
        std::task::Poll::Ready(Err(self.err))
    }

    fn drop_read(&self) {}
}

pub fn connect_to_error(conn: Arc<dyn TunnelConnection>, err: IoError) {
    let termination = Arc::new(Mutex::new(ErrorTermination::new(err)));
    let t2 = termination.clone();
    let _ = conn.connect_io(termination, t2);
}
