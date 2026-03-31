use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::sync::Arc;
use core::fmt::Debug;
use futures::Stream;

use crate::proc_machines::{ProcMachine, LockableSelector};
use crate::spsc::*;

/// A `futures::Stream` that can act as the single consumer for a `SpScItem`.
///
/// It interfaces with a sans-io state machine via 3 type parameters:
/// - `IO`: An object that maintains shared ownership of the sans-io state machine
/// - `ITEM`: The SpScItem channel type
/// - `DATA`: The type of message that the stream receives
///
/// The accessor function `facc` extracts a reference to the SpScItem from the IO.
pub struct ScItemStream<IO, ITEM, DATA>
where
    IO: Send + Debug,
    ITEM: SpScItem<DATA>,
{
    machine: Arc<dyn ProcMachine<IO>>,
    facc: fn(&IO) -> &ITEM,
    _phantom: PhantomData<(ITEM, DATA)>,
}

impl<IO, ITEM, DATA> ScItemStream<IO, ITEM, DATA>
where
    IO: Send + Debug,
    ITEM: SpScItem<DATA>,
{
    pub fn new(machine: Arc<dyn ProcMachine<IO>>, facc: fn(&IO) -> &ITEM) -> Self {
        Self {
            machine,
            facc,
            _phantom: PhantomData,
        }
    }
}

impl<IO, ITEM, DATA> Drop for ScItemStream<IO, ITEM, DATA>
where
    IO: Send + Debug,
    ITEM: SpScItem<DATA>,
{
    fn drop(&mut self) {
        let g = self.machine.lock();
        (self.facc)(&*g).close();
    }
}

// SpScItemStream doesn't contain self-referential data, so it's safe to unpin
impl<IO: Send + Debug, ITEM, DATA> Unpin for ScItemStream<IO, ITEM, DATA> where ITEM: SpScItem<DATA> {}

impl<IO, ITEM, DATA> Stream for ScItemStream<IO, ITEM, DATA>
where
    ITEM: SpScItem<DATA>,
    IO: Send + Debug,
{
    type Item = DATA;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let g = self.machine.lock();
        let item = (self.facc)(&*g);
        let mut receiver: Option<DATA> = None;
        let ret = match item.c_try_read(&mut receiver, None).just_poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(SpScItemState::Waiting) => Poll::Pending,
            Poll::Ready(SpScItemState::Busy) => {
                // Got an item
                Poll::Ready(receiver)
            }
            Poll::Ready(SpScItemState::Closed) => Poll::Ready(None),
            Poll::Ready(SpScItemState::Full | SpScItemState::Failed) => Poll::Ready(None),
        };
        ret
    }
}
