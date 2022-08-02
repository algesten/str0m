use std::io;
use std::slice;

use crate::Addrs;
use crate::UDP_MTU;

use super::{Output, OutputQueue, OutputWriter};

/// Helper to enqueue network output data.
struct OutputEnqueuer {
    addrs: Addrs,
    ptr: *mut OutputQueue,
}

impl OutputEnqueuer {
    /// Creates an enqueuer helper instance.
    ///
    /// SAFETY: The user of this enqueuer must guarantee that the
    /// instance does not outlive the lifetime of `&mut OutputQueue`.
    pub fn new(addrs: Addrs, queue: &mut OutputQueue) -> Self {
        OutputEnqueuer {
            addrs,
            ptr: queue as *mut OutputQueue,
        }
    }

    pub fn get_buffer_writer(&mut self) -> OutputWriter {
        // SAFETY: See `new`
        let queue = unsafe { &mut *self.ptr };

        queue.get_buffer_writer()
    }

    pub fn enqueue(&mut self, buffer: Output) {
        // SAFETY: See `new`
        let queue = unsafe { &mut *self.ptr };

        queue.enqueue(self.addrs, buffer);
    }
}

// SAFETY: The internal raw pointer should be short lived, see `PtrBuffer::set_input`.
unsafe impl Send for PtrBuffer {}

pub(crate) struct PtrBuffer {
    src: Option<(*const u8, usize)>,
    dst: Option<OutputEnqueuer>,
}

impl PtrBuffer {
    pub fn new() -> Self {
        PtrBuffer {
            src: None,
            dst: None,
        }
    }

    /// Sets input to be read via `io::Read`. The data is read via a raw pointer to
    /// avoid lifetime parameters.
    ///
    /// SAFETY: The caller must ensure the [`io::Read::read`] call happens within the
    /// lifetime of `src` &[u8].
    pub unsafe fn set_input(&mut self, src: &[u8]) {
        assert!(self.src.is_none());
        self.src = Some((src.as_ptr(), src.len()));
    }

    pub fn assert_input_was_read(&self) {
        assert!(self.src.is_none(), "PtrBuffer::src is not None");
    }

    /// Sets the output queue to be written to. Must be followed by
    /// `remote_output()`.
    ///
    /// SAFETY: The caller must ensure `remove_output` is called before
    /// the lifetime end of `queue`.
    pub unsafe fn set_output(&mut self, addrs: Addrs, queue: &mut OutputQueue) {
        let enqueuer = OutputEnqueuer::new(addrs, queue);
        self.dst = Some(enqueuer);
    }

    pub fn remove_output(&mut self) {
        self.dst = None;
    }
}

impl io::Read for PtrBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some((ptr, len)) = self.src.take() {
            // SAFETY: this is only safe if the read() of this data is done in the same
            // scope calling set_input().
            let src = unsafe { slice::from_raw_parts(ptr, len) };

            // The read() call must read the entire buffer in one go, we can't fragment it.
            assert!(
                buf.len() >= len,
                "Read buf too small for entire PtrBuffer::src"
            );

            (&mut buf[0..len]).copy_from_slice(src);

            Ok(len)
        } else {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock"))
        }
    }
}

impl io::Write for PtrBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        assert!(len <= UDP_MTU, "Too large DTLS packet: {}", buf.len());

        let enqueuer = self.dst.as_mut().expect("No set_output");
        let mut writer = enqueuer.get_buffer_writer();

        (&mut writer[0..buf.len()]).copy_from_slice(buf);
        let buffer = writer.set_len(buf.len());

        enqueuer.enqueue(buffer);

        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
