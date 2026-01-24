use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Sink;

use crate::proc_machines::ProcMachine;
use crate::spsc::*;
use crate::TunnelError;

/// A `futures::Sink` that can act as the single producer for a `SpScItem`.
///
/// It interfaces with a sans-io state machine via 3 type parameters:
/// - `IO`: An object that maintains shared ownership of the sans-io state machine
/// - `ITEM`: The SpScItem channel type
/// - `DATA`: The type of message that the sink sends
///
/// The accessor function `facc` extracts a reference to the SpScItem from the IO.
pub struct SpItemSink<IO, ITEM, DATA>
where
    ITEM: SpScItem<DATA>,
{
    io: IO,
    facc: fn(&IO) -> &ITEM,
    _phantom: PhantomData<(ITEM, DATA)>,
}

impl<IO, ITEM, DATA> SpItemSink<IO, ITEM, DATA>
where
    ITEM: SpScItem<DATA>,
{
    pub fn new(io: IO, facc: fn(&IO) -> &ITEM) -> Self {
        Self {
            io,
            facc,
            _phantom: PhantomData,
        }
    }
}

impl<IO, ITEM, DATA> Drop for SpItemSink<IO, ITEM, DATA>
where
    ITEM: SpScItem<DATA>,
{
    fn drop(&mut self) {
        (self.facc)(&self.io).close();
    }
}

// SpScItemSink doesn't contain self-referential data, so it's safe to unpin
impl<IO, ITEM, DATA> Unpin for SpItemSink<IO, ITEM, DATA> where ITEM: SpScItem<DATA> {}

impl<IO, ITEM, DATA> Sink<DATA> for SpItemSink<IO, ITEM, DATA>
where
    ITEM: SpScItem<DATA>,
    IO: ProcMachine,
{
    type Error = TunnelError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TunnelError>> {
        let this = self.get_mut();
        let item = (this.facc)(&this.io);
        let ret = match item.p_try_flush(None).just_poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(SpScItemState::Busy) => Poll::Pending,
            Poll::Ready(SpScItemState::Waiting) => Poll::Ready(Ok(())),
            _ => Poll::Ready(Err(TunnelError::StreamDropped)),
        };
        this.io.tick();
        ret
    }

    fn start_send(self: Pin<&mut Self>, data: DATA) -> Result<(), TunnelError> {
        let this = self.get_mut();
        let item = (this.facc)(&this.io);
        let mut sender = Some(data);
        let ret = match item.side_try_write(&mut sender, None) {
            SpScItemState::Full => Ok(()),
            _ => {
                item.close();
                Err(TunnelError::InvalidState)
            }
        };
        this.io.tick();
        ret
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let item = (this.facc)(&this.io);
        let ret = match item.p_try_flush(None).just_poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(SpScItemState::Busy) => Poll::Pending,
            Poll::Ready(SpScItemState::Waiting) => Poll::Ready(Ok(())),
            Poll::Ready(SpScItemState::Closed) => Poll::Ready(Ok(())),
            _ => Poll::Ready(Err(TunnelError::StreamDropped)),
        };
        this.io.tick();
        ret
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let item = (this.facc)(&this.io);
        let ret = match item.p_try_flush(None).just_poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(SpScItemState::Busy) => Poll::Pending,
            Poll::Ready(SpScItemState::Waiting) => Poll::Ready(Ok(())),
            Poll::Ready(SpScItemState::Closed) => Poll::Ready(Ok(())),
            _ => Poll::Ready(Err(TunnelError::StreamDropped)),
        };
        item.close();
        this.io.tick();
        ret
    }
}
