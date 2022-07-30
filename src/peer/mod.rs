mod config;
mod init;
mod inout;
mod ptr_buf;
mod serialize;

use openssl::ssl::SslContext;
use rand::Rng;
use std::collections::{HashSet, VecDeque};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::time::Instant;
use std::{io, mem};

use crate::dtls::{dtls_create_ctx, dtls_ssl_create, Dtls, SrtpKeyMaterial};
use crate::media::Media;
use crate::sdp::{AttributeExt, Sdp};
use crate::sdp::{Fingerprint, IceCreds};
use crate::sdp::{SessionId, Setup};
use crate::stun::StunMessage;
use crate::util::random_id;
use crate::Error;

pub use self::inout::{Answer, Input, NetworkInput, Offer, Output};
use self::inout::{InputInner, NetworkInputInner, NetworkOutput, NetworkOutputWriter};
use self::ptr_buf::{OutputEnqueuer, PtrBuffer};
pub use config::PeerConfig;

/// States the `Peer` can be in.
pub mod state {
    /// First state after creation.
    pub struct Init {}
    /// If we do `create_offer.
    pub struct Offering {}
    /// When we're ready to connect (Offer/Answer exchange is finished).
    pub struct Connecting {}
    /// When we have connected.
    pub struct Connected {}
}

/// A single peer connection.
pub struct Peer<State> {
    /// Config object provided at creation.
    config: PeerConfig,

    /// Unique id of the session, as transmitted on the o= line.
    session_id: SessionId,

    /// Whether this peer is active, passive or actpass.
    setup: Setup,

    /// Queue of output network data.
    output: OutputQueue,

    /// State of STUN.
    stun_state: StunState,

    /// State of DTLS.
    dtls_state: DtlsState,

    /// The configured media (audio/video or datachannel).
    media: Vec<Media>,

    _ph: PhantomData<State>,
}

pub(crate) struct OutputQueue {
    /// Enqueued NetworkOutput to be consumed.
    queue: VecDeque<(SocketAddr, NetworkOutput)>,

    /// Free NetworkOutput instance ready to be reused.
    free: Vec<NetworkOutput>,
}

struct StunState {
    /// Local credentials for STUN. We use one set for all m-lines.
    local_creds: IceCreds,

    /// Remote credentials for STUN. Obtained from SDP.
    remote_creds: HashSet<IceCreds>,

    /// Addresses that have been "unlocked" via STUN. These IP:PORT combos
    /// are now verified for other kinds of data like DTLS, RTP, RTCP...
    verified: HashSet<SocketAddr>,
}

struct DtlsState {
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

impl OutputQueue {
    fn new() -> Self {
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

    pub fn enqueue(&mut self, addr: SocketAddr, buffer: NetworkOutput) {
        self.queue.push_back((addr, buffer));
    }

    pub fn dequeue(&mut self) -> Option<(SocketAddr, &NetworkOutput)> {
        let (addr, out) = self.queue.pop_front()?;

        // It's a bit strange to push the buffer to free already before handing it out to
        // the API consumer. However, Rust borrowing rules means we will not get another
        // change to the state until the API consumer releases the borrowed buffer.
        self.free.push(out);

        let borrowed = self.free.last().unwrap();

        Some((addr, borrowed))
    }
}

impl StunState {
    fn accepts_stun(&self, addr: SocketAddr, stun: &StunMessage<'_>) -> Result<bool, Error> {
        let (local_username, remote_username) = stun.local_remote_username();

        let creds_in_remote_sdp = self
            .remote_creds
            .iter()
            .any(|c| c.username == remote_username);

        if !creds_in_remote_sdp {
            // this is not a fault, the packet might not be for this peer.
            return Ok(false);
        }

        if local_username != self.local_creds.username {
            // this is a bit suspicious... maybe a name clash on the remote username?
            return Err(Error::StunError(format!(
                "STUN local != peer.local ({}): {} != {}",
                addr, local_username, self.local_creds.username
            )));
        }

        if !stun.check_integrity(&self.local_creds.password) {
            // this is also sus.
            return Err(Error::StunError(format!(
                "STUN check_integrity failed ({})",
                addr,
            )));
        }

        Ok(true)
    }

    fn handle_stun<'a>(
        &mut self,
        addr: SocketAddr,
        queue: &mut OutputQueue,
        stun: StunMessage<'a>,
    ) -> Result<(), Error> {
        let reply = stun.reply()?;

        // on the back of a successful (authenticated) stun bind, we update
        // the validated addresses to receive dtls, rtcp, rtp etc.
        if self.verified.insert(addr) {
            trace!("STUN new verified peer ({})", addr);
        }

        let mut writer = queue.get_buffer_writer();
        let len = reply.to_bytes(&self.local_creds.password, &mut writer)?;
        let buffer = writer.set_len(len);

        queue.enqueue(addr, buffer);

        Ok(())
    }

    fn is_stun_verified(&self, addr: &SocketAddr) -> bool {
        self.verified.contains(addr)
    }
}

impl DtlsState {
    fn handle_dtls(
        &mut self,
        addr: SocketAddr,
        output: &mut OutputQueue,
        buf: &[u8],
    ) -> Result<(), Error> {
        let dtls = self.dtls.as_mut().unwrap();

        let enqueuer = unsafe { OutputEnqueuer::new(addr, output) };

        let ptr_buf = dtls.inner_mut()?;
        ptr_buf.set_input(buf); // provide buffer to be read from.
        ptr_buf.set_output(enqueuer); // provide output queue to write to

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

        let ptr_buf = dtls.inner_mut()?;
        // ensure incoming buffer was indeed read by DTLS layer.
        ptr_buf.assert_input_was_read();
        // clean up.
        ptr_buf.remove_output();

        Ok(())
    }
}

impl<T> Peer<T> {
    fn into_state<U>(self) -> Peer<U> {
        // SAFETY: this is fine, because we only change the PhantomData.
        unsafe { mem::transmute(self) }
    }

    pub(crate) fn with_config(config: PeerConfig) -> Result<Peer<state::Init>, Error> {
        let (ctx, local_fingerprint) = dtls_create_ctx()?;

        let mut rng = rand::thread_rng();
        let id = (u64::MAX as f64 * rng.gen::<f64>()) as u64;
        let setup = config.offer_setup;

        let peer = Peer {
            config,
            session_id: SessionId(id),
            setup,
            output: OutputQueue::new(),
            stun_state: StunState {
                local_creds: IceCreds {
                    username: random_id::<8>().to_string(),
                    password: random_id::<24>().to_string(),
                },
                remote_creds: HashSet::new(),
                verified: HashSet::new(),
            },
            dtls_state: DtlsState {
                ctx,
                dtls: None,
                local_fingerprint,
                remote_fingerprints: HashSet::new(),
                srtp_key: None,
            },
            media: vec![],
            _ph: PhantomData,
        };

        Ok(peer)
    }

    fn _accepts(&self, input: &Input<'_>) -> Result<bool, Error> {
        use InputInner::*;
        use NetworkInputInner::*;
        Ok(match &input.0 {
            Tick => panic!("Tick in accepts"),
            Offer(_) => true,  // TODO check against previous
            Answer(_) => true, // TODO check against previous
            Network(addr, data) => {
                if let Stun(stun) = &data.0 {
                    self.stun_state.accepts_stun(*addr, stun)?
                } else {
                    // All other kind of network input must be "unlocked" by STUN recognizing the
                    // ice-ufrag/passwd from the SDP. Any sucessful STUN cause the remote IP/port
                    // combo to be considered associated with this peer.
                    self.stun_state.is_stun_verified(addr)
                }
            }
        })
    }

    fn _handle_input(&mut self, _time: Instant, input: Input<'_>) -> Result<Output, Error> {
        use InputInner::*;
        use NetworkInputInner::*;
        Ok(match input.0 {
            Tick => Output::None,
            Offer(v) => self.handle_offer(v)?.into(),
            Answer(v) => self.handle_answer(v)?.into(),
            Network(addr, data) => {
                match data.0 {
                    Stun(stun) => self.stun_state.handle_stun(addr, &mut self.output, stun)?,
                    Dtls(dtls) => self.dtls_state.handle_dtls(addr, &mut self.output, dtls)?,
                }
                Output::None
            }
        })
    }

    fn _network_output(&mut self) -> Option<(SocketAddr, &NetworkOutput)> {
        self.output.dequeue()
    }

    fn handle_offer(&mut self, offer: Offer) -> Result<Answer, Error> {
        let sdp = &offer.0;
        let x = self.update_from_session_media_attriutes(sdp)?;

        // If we receive an offer, we are not allowed to answer with actpass.
        if self.setup == Setup::ActPass {
            self.setup = if self.config.answer_active {
                Setup::Active
            } else {
                Setup::Passive
            }
        }

        if let Some(remote_setup) = x {
            self.setup = self.setup.compare_to_remote(remote_setup).ok_or_else(|| {
                Error::SdpError(format!(
                    "Incompatible a=setup, local={:?}, remote={:?}",
                    self.setup, remote_setup
                ))
            })?;
        }

        if self.dtls_state.dtls.is_none() && self.setup == Setup::Active {
            // A special, case, if remote offer is actpass or passive, we
            // will assume active role, and can start DTLS at the same time
            // as returning the SDP answer.
            self.start_dtls()?;
        }

        todo!()
    }

    fn handle_answer(&mut self, answer: Answer) -> Result<(), Error> {
        let sdp = &answer.0;
        let x = self.update_from_session_media_attriutes(sdp)?;

        if let Some(remote_setup) = x {
            if remote_setup == Setup::ActPass {
                return Err(Error::SdpError(
                    "Remote incorrectly answered with a=setup:actpass".to_string(),
                ));
            }

            self.setup = self.setup.compare_to_remote(remote_setup).ok_or_else(|| {
                Error::SdpError(format!(
                    "Incompatible a=setup, local={:?}, remote={:?}",
                    self.setup, remote_setup
                ))
            })?;
        }

        if self.dtls_state.dtls.is_none() {
            self.start_dtls()?;
        }

        todo!()
    }

    fn update_from_session_media_attriutes(&mut self, sdp: &Sdp) -> Result<Option<Setup>, Error> {
        let mut setups = vec![];

        // Session level
        if let Some(setup) = sdp.session.attrs.setup() {
            setups.push(setup);
        }
        if let Some(creds) = sdp.session.attrs.ice_creds() {
            self.stun_state.remote_creds.insert(creds);
        }
        if let Some(fp) = sdp.session.attrs.fingerprint() {
            self.dtls_state.remote_fingerprints.insert(fp);
        }

        // M-line level
        for mline in &sdp.media_lines {
            if let Some(setup) = mline.attrs.setup() {
                setups.push(setup);
            }
            if let Some(creds) = mline.attrs.ice_creds() {
                self.stun_state.remote_creds.insert(creds);
            }
            if let Some(fp) = mline.attrs.fingerprint() {
                self.dtls_state.remote_fingerprints.insert(fp);
            }
        }

        let mut setup = None;

        if !setups.is_empty() {
            let first = &setups[0];
            if !setups.iter().all(|s| s == first) {
                return Err(Error::SdpError(
                    "Remote SDP got conflicting a=setup lines".to_string(),
                ));
            }
            setup = Some(*first);
        }

        Ok(setup)
    }

    fn start_dtls(&mut self) -> Result<(), Error> {
        assert!(self.dtls_state.dtls.is_none());
        assert!(self.setup != Setup::ActPass);

        let active = self.setup == Setup::Active;

        let ssl = dtls_ssl_create(&self.dtls_state.ctx)?;
        let dtls = Dtls::new(ssl, PtrBuffer::new(), active);
        self.dtls_state.dtls = Some(dtls);

        Ok(())
    }
}

impl Peer<state::Connected> {
    /// Tests whether this [`Peer`] accepts the input.
    ///
    /// This is useful in a server scenario when multiplexing several Peers on the same UDP port.
    pub fn accepts(&self, input: &Input<'_>) -> Result<bool, Error> {
        self._accepts(input)
    }

    /// Provide input to this Peer.
    ///
    /// Any input can potentially result in multiple output. For example, one DTLS UDP packet
    /// might result in multiple outgoing DTLS UDP packets.
    pub fn handle_input<'a>(&mut self, time: Instant, input: Input<'a>) -> Result<Output, Error> {
        self._handle_input(time, input)
    }

    /// Poll network output.
    ///
    /// For every input provided, this needs to be polled until it returns `None`.
    pub fn network_output(&mut self) -> Option<(SocketAddr, &NetworkOutput)> {
        self._network_output()
    }
}
