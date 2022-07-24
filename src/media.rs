//! Media (m-line) related stuff.

use crate::sdp::{MediaLine, MediaType};

///
pub struct Media {
    /// The corresponding transceiver config in the m-line.
    media_line: MediaLine,

    /// Whether this transceiver has been negotiated with the remote side.
    need_negotiating: bool,
}

impl Media {
    pub fn new(typ: MediaType) -> Self {
        todo!()
    }
}
