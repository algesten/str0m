use std::collections::VecDeque;
use std::io;

use crate::net::DatagramSend;

#[derive(Default)]
pub struct IoBuffer {
    pub incoming: Vec<u8>,
    pub outgoing: VecDeque<DatagramSend>,
}

impl IoBuffer {
    pub(crate) fn set_incoming(&mut self, buf: &[u8]) {
        assert!(self.incoming.is_empty());
        self.incoming.resize(buf.len(), 0);
        self.incoming.copy_from_slice(buf);
    }

    pub(crate) fn pop_outgoing(&mut self) -> Option<DatagramSend> {
        self.outgoing.pop_front()
    }
}

impl io::Read for IoBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.incoming.len();

        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock"));
        }

        // read buffer must read entire packet in one go.
        // we can't fragment incoming datagrams.
        assert!(buf.len() >= n);

        buf[0..n].copy_from_slice(&self.incoming);
        self.incoming.truncate(0);

        Ok(n)
    }
}

impl io::Write for IoBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let dsend = buf.to_vec().into();

        self.outgoing.push_back(dsend);

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
