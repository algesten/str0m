use openssl::ssl::SslContext;
use std::collections::HashSet;
use std::io;

use crate::dtls::tls::dtls_ssl_create;
use crate::output::{OutputQueue, PtrBuffer};
use crate::sdp::{Fingerprint, SessionId};
use crate::util::{Addrs, Ts};
use crate::Error;

pub use self::tls::SrtpKeyMaterial;
use self::tls::{dtls_create_ctx, Dtls};

mod tls;

pub(crate) struct DtlsState {
    /// Session id for the Peer.
    session_id: SessionId,

    /// Whether we are the initiating side of the DTLS handshake.
    active: bool,

    /// DTLS context for this peer.
    ///
    /// TODO: Should we share this for the entire app?
    ctx: SslContext,

    /// DTLS wrapper a special stream we read/write DTLS packets to.
    /// Instantiation is delayed until we know whether this instance is
    /// active or passive, which is evident from the a=setup:actpass,
    /// a=setup:active or a=setup:passive in the negotiation.
    dtls: Option<Dtls<PtrBuffer>>,

    /// Local fingerprint for DTLS. We use one certificate per peer.
    local_fingerprint: Fingerprint,

    /// Remote fingerprints for DTLS. Obtained from SDP.
    remote_fingerprints: HashSet<Fingerprint>,

    /// The master key for the SRTP decryption/encryption.
    /// Obtained as a side effect of the DTLS handshake.
    srtp_key: Option<SrtpKeyMaterial>,
}

impl DtlsState {
    pub fn new(session_id: SessionId) -> Result<Self, Error> {
        let (ctx, local_fingerprint) = dtls_create_ctx()?;

        Ok(DtlsState {
            session_id,
            active: false,
            ctx,
            dtls: None,
            local_fingerprint,
            remote_fingerprints: HashSet::new(),
            srtp_key: None,
        })
    }

    pub fn add_remote_fingerprint(&mut self, id: &SessionId, fp: Fingerprint) {
        let line = format!("{:?} Added remote fingerprint: {:?}", id, fp);
        if self.remote_fingerprints.insert(fp) {
            trace!(line);
        }
    }

    pub fn init_dtls(&mut self, active: bool) -> Result<(), Error> {
        assert!(self.dtls.is_none());
        info!("{:?} Init DTLS active: {}", self.session_id, active);

        self.active = active;
        let ssl = dtls_ssl_create(&self.ctx)?;
        let dtls = Dtls::new(ssl, PtrBuffer::new(), active);
        self.dtls = Some(dtls);

        Ok(())
    }

    pub fn is_inited(&self) -> bool {
        self.dtls.is_some()
    }

    pub fn initiate_handshake(
        &mut self,
        _time: Ts,
        addrs: Addrs,
        output: &mut OutputQueue,
    ) -> Result<(), Error> {
        if !self.active {
            return Ok(());
        }

        let dtls = match self.dtls.as_mut() {
            Some(v) => v,
            None => return Ok(()),
        };

        if dtls.is_handshaken() {
            return Ok(());
        }

        debug!("{:?} DTLS initiate handshake", self.session_id);

        let ptr_buf = dtls.inner_mut();

        // Ensure no hangover state.
        ptr_buf.assert_input_was_read();

        // SAFETY: We must call ptr_buf.remove_output() within `output` ref lifetime.
        unsafe { ptr_buf.set_output(addrs, output) }; // provide output queue to write to

        // This should write stuff into the output.
        dtls.handshaken()?;

        let ptr_buf = dtls.inner_mut();
        // clean up.
        ptr_buf.remove_output();

        Ok(())
    }

    pub fn handle_dtls(
        &mut self,
        _time: Ts,
        addrs: Addrs,
        output: &mut OutputQueue,
        buf: &[u8],
    ) -> Result<(), Error> {
        let dtls = self.dtls.as_mut().expect("Mut have inited DTLS");

        let ptr_buf = dtls.inner_mut();

        // SAFETY: The io::Read call of ptr_buf must happen within the lifetime of buf.
        unsafe { ptr_buf.set_input(buf) }; // provide buffer to be read from.

        // SAFETY: We must call ptr_buf.remove_output() within `output` ref lifetime.
        unsafe { ptr_buf.set_output(addrs, output) }; // provide output queue to write to

        let completed = dtls.complete_handshake_until_block()?;

        if completed && self.srtp_key.is_none() {
            let (srtp_key, fp) = dtls
                .take_srtp_key_material()
                .expect("SRTP key material on DTLS handshake completion");

            // Before accepting the key material, check the fingerprint is known from the SDP.
            if !self.remote_fingerprints.contains(&fp) {
                let err = io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unknown remote DTLS fingerrint",
                );
                return Err(err.into());
            }

            self.srtp_key = Some(srtp_key);
        }

        if completed {
            // TODO: dtls.read() SCTP data.
        }

        let ptr_buf = dtls.inner_mut();
        // ensure incoming buffer was indeed read by DTLS layer.
        ptr_buf.assert_input_was_read();
        // clean up.
        ptr_buf.remove_output();

        Ok(())
    }

    pub fn local_fingerprint(&self) -> &Fingerprint {
        &self.local_fingerprint
    }

    pub fn is_handshaken(&self) -> bool {
        self.dtls
            .as_ref()
            .map(|d| d.is_handshaken())
            .unwrap_or(false)
    }
}
