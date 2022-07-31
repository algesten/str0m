mod change;
mod config;
mod inout;
mod peer_init;
mod ptr_buf;
mod serialize;

use openssl::ssl::SslContext;
use rand::Rng;
use std::collections::{HashSet, VecDeque};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::{io, mem};

use crate::dtls::{dtls_create_ctx, dtls_ssl_create, Dtls, SrtpKeyMaterial};
use crate::ice::IceState;
use crate::media::Media;
use crate::sdp::Fingerprint;
use crate::sdp::{Mid, Sdp};
use crate::sdp::{SessionId, Setup};
use crate::Error;

use self::change::Changes;
pub use self::inout::{Answer, Io, NetworkInput, Offer};
use self::inout::{NetworkOutput, NetworkOutputWriter};
use self::ptr_buf::{OutputEnqueuer, PtrBuffer};
pub use change::{change_state, ChangeSet};
pub use config::PeerConfig;
pub use peer_init::ConnectionResult;

/// States the `Peer` can be in.
pub mod state {
    /// First state after creation.
    pub struct Init(());

    /// While doing the initial offer, we are only accepting an answer. This is before
    /// any UDP traffic has started.
    pub struct InitialOffering(());

    /// When we're ready to connect (Offer/Answer exchange is finished).
    pub struct Connecting(());

    /// When we have connected.
    pub struct Connected(());

    /// While we have made a new offer.
    pub struct Offering(());
}

/// A single peer connection.
///
/// # Starting by creating an offer
///
/// ```no_run
/// # fn main() -> Result<(), str0m::Error> {
/// use std::convert::TryFrom;
/// use std::net::SocketAddr;
/// use std::time::Instant;
/// use str0m::*;
///
/// // 1. Create a Peer from a PeerConfig.
/// let peer_init = PeerConfig::new().build()?;
///
/// // 2. To create an offer, we must add media, or a data channel.
/// let change_set = peer_init.change_set();
/// let (offer, peer_offering) = change_set.add_data_channel().apply();
///
/// // 3. Send the offer _somehow_ to the remote peer and receive
/// //    the answer back (via websocket for instance).
/// let answer = todo!();
/// let mut peer_connecting = peer_offering.accept_answer(answer)?;
///
/// // 4. Loop send/receive UDP data until connected.
/// let peer_connected = loop {
///     while let Some((addr, data_out)) = peer_connecting.io().network_output() {
///         // TODO: send data_out to addr via UDP socket.
///     }
///
///     // Obtain data from socket.
///     let (addr, data_in): (SocketAddr, &[u8]) = todo!();
///     // This should be the receive time as close to the network
///     // socket read as possible.
///     let time = Instant::now();
///
///     // Parse the network data.
///     let network = NetworkInput::try_from(data_in)?;
///
///     // Feed input data to peer.
///     peer_connecting.io().network_input(time, addr, network)?;
///
///     match peer_connecting.try_connect() {
///         ConnectionResult::Connecting(v) => peer_connecting = v,
///         ConnectionResult::Connected(v) => break v,
///     }
/// };
///
/// // 5. Use the connected `peer_connected` instance.
/// # Ok(())}
/// ```
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
    ice_state: IceState,

    /// State of DTLS.
    dtls_state: DtlsState,

    /// The configured media (audio/video or datachannel). "configured"
    /// means the lines contain only the negotiated subset of possible
    /// codecs/features.
    media: Vec<Media>,

    /// Changes to be made to the media state. These are held
    /// as pending until the remote side confirms the changes
    /// in an `Answer`.
    pending_changes: Option<Changes>,

    _ph: PhantomData<State>,
}

pub(crate) struct OutputQueue {
    /// Enqueued NetworkOutput to be consumed.
    queue: VecDeque<(SocketAddr, NetworkOutput)>,

    /// Free NetworkOutput instance ready to be reused.
    free: Vec<NetworkOutput>,
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

impl DtlsState {
    fn add_remote_fingerprint(&mut self, id: &SessionId, fp: Fingerprint) {
        let line = format!("{:?} Added remote fingerprint: {:?}", id, fp);
        if self.remote_fingerprints.insert(fp) {
            trace!(line);
        }
    }

    fn handle_dtls(
        &mut self,
        addr: SocketAddr,
        output: &mut OutputQueue,
        buf: &[u8],
    ) -> Result<(), Error> {
        let dtls = self.dtls.as_mut().unwrap();

        let enqueuer = unsafe { OutputEnqueuer::new(addr, output) };

        let ptr_buf = dtls.inner_mut()?;
        // SAFETY: The io::Read call of ptr_buf must happen within the lifetime of buf.
        unsafe { ptr_buf.set_input(buf) }; // provide buffer to be read from.
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

        let id = if let Some(id) = config.session_id {
            id
        } else {
            // We always want exactly 18 char 64 bit session numbers.
            loop {
                const MAX_ID: u64 = 999_999_999_999_999_999;
                let x = (MAX_ID as f64 * rng.gen::<f64>()) as u64;
                if x.to_string().chars().count() == 18 {
                    break x;
                }
            }
        };

        let setup = config.offer_setup;

        let session_id = SessionId(id);

        let mut ice_state = IceState::new(config.ice_lite);

        for c in &config.local_candidates {
            ice_state.add_local_candidate(&session_id, c.clone());
        }

        if config.end_of_candidates {
            if ice_state.local_candidates().is_empty() {
                return Err(Error::Config(
                    "Illegal PeerConfig without candidates and end-of-candidates".to_string(),
                ));
            }

            ice_state.set_local_end_of_candidates(&session_id);
        }

        let peer = Peer {
            config,
            session_id,
            setup,
            output: OutputQueue::new(),
            ice_state,
            dtls_state: DtlsState {
                ctx,
                dtls: None,
                local_fingerprint,
                remote_fingerprints: HashSet::new(),
                srtp_key: None,
            },
            media: vec![],
            pending_changes: None,
            _ph: PhantomData,
        };

        Ok(peer)
    }

    fn set_pending_changes(&mut self, changes: Changes) -> Offer {
        assert!(self.pending_changes.is_none());
        debug!("{:?} Set pending changes", self.session_id);

        self.pending_changes = Some(changes);

        // SDP from current state and modified by the pending changes.
        let sdp = self.as_sdp();

        Offer(sdp)
    }

    fn do_handle_offer(&mut self, offer: Offer) -> Result<Answer, Error> {
        assert!(self.pending_changes.is_none());

        let sdp = &offer.0;
        let x = self.update_session_from_remote_sdp(sdp, true)?;

        // If we receive an offer, we are not allowed to answer with actpass.
        if self.setup == Setup::ActPass {
            self.setup = if self.config.answer_active {
                Setup::Active
            } else {
                Setup::Passive
            };
            debug!(
                "{:?} Change setup for answer: {} -> {}",
                self.session_id,
                Setup::ActPass,
                self.setup
            );
        }

        if let Some(remote_setup) = x {
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

        self.update_media_from_offer(offer)?;

        let answer = Answer(self.as_sdp());

        Ok(answer)
    }

    fn do_handle_answer(&mut self, answer: Answer) -> Result<(), Error> {
        assert!(self.pending_changes.is_some());

        let sdp = &answer.0;
        let x = self.update_session_from_remote_sdp(sdp, false)?;

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

        // this is checked above.
        let changes = self.pending_changes.take().unwrap();

        self.update_media_from_changes(changes, answer)?;

        Ok(())
    }

    fn update_session_from_remote_sdp(
        &mut self,
        sdp: &Sdp,
        remote_is_offer: bool,
    ) -> Result<Option<Setup>, Error> {
        debug!("{:?} Update session from remote SDP", self.session_id);

        if self.ice_state.can_set_controlling() {
            let local_is_ice_lite = self.config.ice_lite;
            let remote_is_ice_lite = sdp.session.ice_lite();
            let local_sent_offer = !remote_is_offer;
            let local_is_controlling = match (local_is_ice_lite, remote_is_ice_lite) {
                // if both are ice-lite, local is controlling if local sent offer.
                (true, true) => local_sent_offer,
                // remote is not ice-lite, remote is controlling.
                (true, false) => false,
                // local is not ice-lite, local is controlling.
                (false, true) => true,
                // if none is ice-lite, local is controlling if local sent offer.
                (false, false) => local_sent_offer,
            };
            self.ice_state
                .set_controlling(&self.session_id, local_is_controlling);
        }

        let mut setups = vec![];

        // Session level
        if let Some(setup) = sdp.session.setup() {
            setups.push(setup);
        }
        if let Some(creds) = sdp.session.ice_creds() {
            self.ice_state.add_remote_creds(&self.session_id, creds);
        }
        if let Some(fp) = sdp.session.fingerprint() {
            self.dtls_state.add_remote_fingerprint(&self.session_id, fp);
        }

        // M-line level
        for mline in &sdp.media_lines {
            if let Some(setup) = mline.setup() {
                setups.push(setup);
            }
            if let Some(creds) = mline.ice_creds() {
                self.ice_state.add_remote_creds(&self.session_id, creds);
            }
            if let Some(fp) = mline.fingerprint() {
                self.dtls_state.add_remote_fingerprint(&self.session_id, fp);
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

    fn update_media_from_offer(&mut self, offer: Offer) -> Result<(), Error> {
        debug!("{:?} Update media from Offer", self.session_id);

        // check_consistent ensures the m-lines contain all we need.
        if let Some(problem) = offer.0.check_consistent() {
            return Err(Error::SdpError(problem));
        }

        self.update_existing_media_from_sdp(&offer.0);

        for m in offer.0.media_lines.into_iter() {
            let remote_mid = m.mid();

            // Skip lines we already have.
            let exists = self.media.iter().any(|e| remote_mid == e.mid());
            if exists {
                continue;
            }

            debug!(
                "{:?} Add new media with mid: {}",
                self.session_id, remote_mid
            );

            let mut media = Media::new(m);
            media.narrow_remote_to_locally_accepted();

            self.media.push(media);
        }

        Ok(())
    }

    fn update_media_from_changes(&mut self, changes: Changes, answer: Answer) -> Result<(), Error> {
        debug!("{:?} Update media from pending changes", self.session_id);

        // check_consistent ensures the m-lines contain all we need.
        if let Some(problem) = answer.0.check_consistent() {
            return Err(Error::SdpError(problem));
        }

        self.update_existing_media_from_sdp(&answer.0);

        for mut media in changes.new_media_lines() {
            let local_mid = media.mid();
            let remote = answer.0.media_lines.iter().find(|m| local_mid == m.mid());

            if let Some(remote) = remote {
                debug!(
                    "{:?} Add new media with mid: {}",
                    self.session_id, local_mid
                );

                media.narrow_local_to_remotely_accepted(remote);

                self.media.push(media);
            } else {
                return Err(Error::SdpError(format!(
                    "Remote answer missing mid: {}",
                    local_mid
                )));
            }
        }

        Ok(())
    }

    fn update_existing_media_from_sdp(&mut self, sdp: &Sdp) {
        for m in &sdp.media_lines {
            if let Some(media) = self.media.iter_mut().find(|e| m.mid() == e.mid()) {
                // We have the local media.

                // Direction changes.
                let wanted_dir = m.direction().invert();
                if media.direction() != wanted_dir {
                    debug!(
                        "{:?} Direction change for mid ({}): {} -> {}",
                        self.session_id,
                        media.mid(),
                        media.direction(),
                        wanted_dir
                    );

                    media.set_direction(wanted_dir);
                    todo!(); // emit event that direction changed
                }
            }
        }
    }

    fn start_dtls(&mut self) -> Result<(), Error> {
        info!("{:?} Start DTLS", self.session_id);

        assert!(self.dtls_state.dtls.is_none());
        assert!(self.setup != Setup::ActPass);

        let active = self.setup == Setup::Active;

        let ssl = dtls_ssl_create(&self.dtls_state.ctx)?;
        let dtls = Dtls::new(ssl, PtrBuffer::new(), active);
        self.dtls_state.dtls = Some(dtls);

        Ok(())
    }

    /// Create a new Mid that doesn't already exist.
    pub(crate) fn new_mid(&self) -> Mid {
        loop {
            let mid = Mid::new();
            if self.media.iter().any(|m| m.mid() == mid) {
                continue;
            }
            break mid;
        }
    }
}

impl Peer<state::Connected> {
    /// Make a modification to the session.
    ///
    /// The offer must be provided _in some way_ to the remote side.
    pub fn change_set(self) -> ChangeSet<state::Connected, change_state::NoChange> {
        info!("{:?} Create ChangeSet", self.session_id);
        ChangeSet::new(self)
    }

    /// Do network IO.
    pub fn io(&mut self) -> Io<'_, state::Connected> {
        Io(self)
    }
}

impl Peer<state::Offering> {
    /// Accept an answer from the remote side.
    pub fn accept_answer(mut self, answer: Answer) -> Result<Peer<state::Connected>, Error> {
        info!("{:?} Accept answer", self.session_id);
        self.do_handle_answer(answer)?;
        Ok(self.into_state())
    }

    /// Abort the changes.
    ///
    /// Goes back to a state where we can accept an offer from the remote side instead.
    pub fn rollback(mut self) -> Peer<state::Connected> {
        info!("{:?} Rollback offer", self.session_id);
        self.pending_changes.take();
        self.into_state()
    }

    /// Do network IO.
    pub fn io(&mut self) -> Io<'_, state::Offering> {
        Io(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn peer_is_send() {
        fn is_send<T: Send>(_t: T) {}
        let peer = PeerConfig::new().build().unwrap();
        is_send(peer);
    }
}
