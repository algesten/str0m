mod ptr_buf;

use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};

use crate::Addrs;
use crate::UDP_MTU;
pub(crate) use ptr_buf::PtrBuffer;

#[derive(Clone)]
pub struct Output(Box<[u8; UDP_MTU]>, usize);

impl Output {
    pub(crate) fn new() -> Self {
        Output(Box::new([0_u8; UDP_MTU]), 0)
    }

    /// This provides _the entire_ buffer to write. `set_len` must be done on
    /// the writer onoce write is complete.
    pub(crate) fn into_writer(self) -> OutputWriter {
        OutputWriter(self, false)
    }
}

impl Deref for Output {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[0..self.1]
    }
}

/// RAII guard for writing to [`Output`].
pub(crate) struct OutputWriter(Output, bool);

impl OutputWriter {
    #[must_use]
    pub fn set_len(mut self, len: usize) -> Output {
        assert!(len <= self.0 .0.len());
        self.1 = true;
        self.0 .1 = len;
        self.0
    }
}

impl Deref for OutputWriter {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0 .0[..]
    }
}

impl DerefMut for OutputWriter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0 .0[..]
    }
}

pub(crate) struct OutputQueue {
    /// Enqueued NetworkOutput to be consumed.
    queue: VecDeque<(Addrs, Output)>,

    /// Free NetworkOutput instance ready to be reused.
    free: Vec<Output>,
}

impl OutputQueue {
    pub fn new() -> Self {
        const MAX_QUEUE: usize = 20;
        OutputQueue {
            queue: VecDeque::with_capacity(MAX_QUEUE),
            free: vec![Output::new(); MAX_QUEUE],
        }
    }

    pub fn get_buffer_writer(&mut self) -> OutputWriter {
        if self.free.is_empty() {
            Output::new().into_writer()
        } else {
            self.free.pop().unwrap().into_writer()
        }
    }

    pub fn enqueue(&mut self, addrs: Addrs, data: Output) {
        self.queue.push_back((addrs, data));
    }

    pub fn dequeue(&mut self) -> Option<(Addrs, &[u8])> {
        let (addrs, data) = self.queue.pop_front()?;

        // It's a bit strange to push the buffer to free already before handing it out to
        // the API consumer. However, Rust borrowing rules means we will not get another
        // change to the state until the API consumer releases the borrowed buffer.
        self.free.push(data);
        let borrowed = self.free.last().unwrap();

        Some((addrs, borrowed))
    }
}
