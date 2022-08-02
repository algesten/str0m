mod ptr_buf;

use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};

use crate::util::Addrs;
use crate::UDP_MTU;
pub(crate) use ptr_buf::PtrBuffer;

#[derive(Clone)]
pub struct NetworkOutput(Box<[u8; UDP_MTU]>, usize);

impl NetworkOutput {
    pub(crate) fn new() -> Self {
        NetworkOutput(Box::new([0_u8; UDP_MTU]), 0)
    }

    /// This provides _the entire_ buffer to write. `set_len` must be done on
    /// the writer onoce write is complete.
    pub(crate) fn into_writer(self) -> NetworkOutputWriter {
        NetworkOutputWriter(self, false)
    }
}

impl Deref for NetworkOutput {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[0..self.1]
    }
}

/// RAII guard for writing to [`NetworkOutput`].
pub(crate) struct NetworkOutputWriter(NetworkOutput, bool);

impl NetworkOutputWriter {
    #[must_use]
    pub fn set_len(mut self, len: usize) -> NetworkOutput {
        assert!(len <= self.0 .0.len());
        self.1 = true;
        self.0 .1 = len;
        self.0
    }
}

impl Deref for NetworkOutputWriter {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0 .0[..]
    }
}

impl DerefMut for NetworkOutputWriter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0 .0[..]
    }
}

pub(crate) struct OutputQueue {
    /// Enqueued NetworkOutput to be consumed.
    queue: VecDeque<(Addrs, NetworkOutput)>,

    /// Free NetworkOutput instance ready to be reused.
    free: Vec<NetworkOutput>,
}

impl OutputQueue {
    pub fn new() -> Self {
        const MAX_QUEUE: usize = 20;
        OutputQueue {
            queue: VecDeque::with_capacity(MAX_QUEUE),
            free: vec![NetworkOutput::new(); MAX_QUEUE],
        }
    }

    pub fn get_buffer_writer(&mut self) -> NetworkOutputWriter {
        if self.free.is_empty() {
            NetworkOutput::new().into_writer()
        } else {
            self.free.pop().unwrap().into_writer()
        }
    }

    pub fn enqueue(&mut self, addrs: Addrs, data: NetworkOutput) {
        self.queue.push_back((addrs, data));
    }

    pub fn dequeue(&mut self) -> Option<(Addrs, &NetworkOutput)> {
        let (addrs, data) = self.queue.pop_front()?;

        // It's a bit strange to push the buffer to free already before handing it out to
        // the API consumer. However, Rust borrowing rules means we will not get another
        // change to the state until the API consumer releases the borrowed buffer.
        self.free.push(data);
        let borrowed = self.free.last().unwrap();

        Some((addrs, borrowed))
    }
}
