use crate::dtls::{dtls_create_ctx, DtlsEvent, SrtpKeyMaterial};
use crate::media::{IngressStream, Media};
use crate::rt;
use crate::rt::{mpsc, oneshot};
use crate::rtc::RtcSession;
use crate::sdp::*;
use crate::server::ServerOut;
use crate::srtp::SrtpContext;
use crate::srtp::SrtpKey;
use crate::util::rand_id_s;
use crate::util::Ts;
use crate::{Error, ErrorKind};
use rand::prelude::*;
use std::collections::HashSet;
use std::net::SocketAddr;

/// Top level organizing unit for a remote peer.
///
/// Peer is created by receiving an initial SDP. The values of the parsed SDP
/// are held in Peer. Peer is a record keeper of things happening in an RTCSession.
#[derive(Debug)]
pub struct Peer {
    /// Our local id for this peer. This id stays fixed, also when
    /// clients restart/reconnect and come in using a new remote_id. We use
    /// this for the o= line in SDPs produced.
    pub local_id: SessionId,
    /// This is the session id from the remote SDP o= line.
    pub remote_id: SessionId,
    /// Info about the local side, specific to this Peer
    pub local: LocalInfo,

    /// Collection of media definitions against the peer. The m=lines.
    pub media: Vec<Media>,

    /// Sender of peer packet, so we can clone into places that needs to send PeerInput.
    pub tx: mpsc::Sender<PeerInput>,
    /// Input to peer_main_loop.
    rx: mpsc::Receiver<PeerInput>,

    /// Last time we got a STUN packet, used for cleanup.
    last_stun: Ts,

    /// the WebRTC session.
    rtc: Option<RtcSession>,
}

/// Info about the local side of a Peer.
///
/// This is required to respond to incoming SDP.
#[derive(Debug, Clone)]
pub struct LocalInfo {
    /// Local ice candidates.
    pub candidates: Vec<Candidate>,
    /// Fingerprint for cert in dtls_ctx.
    pub fingerprint: Fingerprint,
    /// Our ice credentials for this peer. We use one single for all m-lines.
    pub ice_creds: IceCreds,
}

/// Credentials for STUN packages.
///
/// By matching IceCreds in STUN to SDP, we know which STUN belongs to which Peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IceCreds {
    // From a=ice-ufrag
    pub username: String,
    // From a=ice-pwd
    pub password: String,
}

/// Handle for input to a Peer.
///
/// For every peer, there is a Peer - PeerHandle pair. The PeerHandle is used on the server
/// level to handle STUN and push incoming UDP packets into the Peer.
#[derive(Debug)]
pub struct PeerHandle {
    pub local_id: SessionId,
    pub remote_id: SessionId,
    pub local: LocalInfo,
    pub remote_creds: HashSet<IceCreds>,
    pub verified: HashSet<SocketAddr>,
    pub tx: mpsc::Sender<PeerInput>,
    pub last_used: Ts,
}

impl Peer {
    pub fn new(candidates: &[Candidate], tx_server: ServerOut) -> Self {
        // spec: It is RECOMMENDED that the sess-id be constructed by generating a 64-bit
        // quantity with the two highest bits being set to zero and the remaining 62 bits being
        // cryptographically random
        let local_id = SessionId(random::<u64>() >> 2);

        // Each peer has it's own tls context
        let (dtls_ctx, fingerprint) = dtls_create_ctx().expect("dtls_create_ctx");

        let rtc = RtcSession::new(dtls_ctx, tx_server);

        let (tx, rx) = mpsc::channel(10);

        Peer {
            local_id,
            remote_id: SessionId(0),
            local: LocalInfo {
                candidates: candidates.to_vec(),
                fingerprint,
                ice_creds: IceCreds {
                    username: rand_id_s(8),
                    password: rand_id_s(24),
                },
            },
            media: vec![],
            tx,
            rx,
            last_stun: Ts::ZERO,
            rtc: Some(rtc),
        }
    }

    pub fn handle(&self) -> PeerHandle {
        PeerHandle {
            local_id: self.local_id.clone(),
            remote_id: self.remote_id.clone(),
            local: self.local.clone(),
            remote_creds: self.remote_creds(),
            verified: HashSet::new(),
            tx: self.tx.clone(),
            last_used: Ts::now(),
        }
    }

    /// Consuming "handler" that handles PeerInput one by one.
    ///
    /// This is used in a spawn().
    pub async fn peer_main_loop(self) {
        if let Err(e) = self.peer_main_loop_run().await {
            warn!("Peer main loop end with error: {:?}", e);
        } else {
            info!("Peer main loop end");
        }
    }

    async fn peer_main_loop_run(mut self) -> Result<(), Error> {
        // The RTCSession is taken out of Peer so we can handle &mut references to
        // both in parallell without upsetting the borrow checker.
        let mut rtc = self.rtc.take().expect("Take RTCSession");

        // Launch a loop to send periodical receiver reports.
        {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
            let mut tx = self.tx.clone();
            rt::spawn(async move {
                loop {
                    interval.tick().await;
                    if tx.send(PeerInput::Periodical).await.is_err() {
                        // receiver gone
                        break;
                    }
                }
            });
        }

        // loop the entire lifetime of the peer
        loop {
            if let Some(op) = self.rx.recv().await {
                match op {
                    PeerInput::StunUpdate(timestamp) => {
                        self.last_stun = timestamp;
                    }

                    PeerInput::SdpOffer(sdp, tx) => {
                        rtc.update_from_sdp(&sdp)?;
                        self.handle_sdp_offer(&sdp, tx)?;
                    }

                    PeerInput::PeerUdp(udp) => {
                        rtc.handle_udp(&mut self, udp).await;
                    }

                    PeerInput::DtlsEvent(dtls_ev) => self.handle_dtls_ev(&mut rtc, dtls_ev)?,

                    PeerInput::Periodical => {
                        rtc.send_periodical_reports(&mut self).await;
                    }
                }
            } else {
                trace!("Input ended");
                break;
            }
        }

        Ok(())
    }

    fn handle_sdp_offer(
        &mut self,
        sdp_offer: &Sdp,
        tx: oneshot::Sender<SdpAnswer>,
    ) -> Result<(), Error> {
        self.apply_remote_sdp(sdp_offer)?;

        let answer = SdpAnswer {
            sdp: self.create_local_sdp(),
            remote_creds: self.remote_creds(),
        };

        tx.send(answer).expect("tx.send answer sdp");

        Ok(())
    }

    fn remote_creds(&self) -> HashSet<IceCreds> {
        self.media.iter().map(|m| &m.ice_creds).cloned().collect()
    }

    fn handle_dtls_ev(&mut self, rtc: &mut RtcSession, dtls_ev: DtlsEvent) -> Result<(), Error> {
        match dtls_ev {
            DtlsEvent::Connected(addr, fp, key) => self.handle_dtls_connected(rtc, addr, fp, key),
            DtlsEvent::Error(addr, err) => {
                err!(ErrorKind::Dtls, "DTLS error ({}): {}", addr, err).into()
            }
        }
    }

    fn handle_dtls_connected(
        &mut self,
        rtc: &mut RtcSession,
        addr: SocketAddr,
        fp: Fingerprint,
        key: SrtpKeyMaterial,
    ) -> Result<(), Error> {
        if !self.has_remote_fingerprint(&fp) {
            return err!(
                ErrorKind::Dtls,
                "DTLS error ({}): no matching fingerprint",
                addr
            )
            .into();
        }

        if let Some(conn) = rtc.connection_by_remote_addr(&addr) {
            let key_rx = SrtpKey::new(&key, true);
            let key_tx = SrtpKey::new(&key, false);

            let srtp_rx = SrtpContext::new(key_rx);
            let srtp_tx = SrtpContext::new(key_tx);

            conn.set_srtp_context(srtp_rx, srtp_tx);
        } else {
            return err!(
                ErrorKind::Dtls,
                "DTLS error ({}): no RtcConnection for address",
                addr
            )
            .into();
        }

        info!("DTLS connected with SRTP key material ({})", addr);
        Ok(())
    }

    fn has_remote_fingerprint(&self, fp: &Fingerprint) -> bool {
        for media in &self.media {
            if media.fingerprint == *fp {
                return true;
            }
        }
        false
    }

    pub fn media_by_ingress_ssrc(&mut self, ssrc: u32) -> Option<&mut Media> {
        self.media.iter_mut().find(|m| m.has_ingress_ssrc(ssrc))
    }

    pub fn media_by_mid(&mut self, mid: &str) -> Option<&mut Media> {
        self.media.iter_mut().find(|m| m.media_id.0 == mid)
    }

    pub fn active_ingress<'a>(&'a mut self, into: &mut Vec<&'a mut IngressStream>) {
        for m in &mut self.media {
            m.active_ingress(into);
        }
    }
}

/// Kinds of input from a Server to a Peer.
///
/// Sent via PeerHandle.
#[derive(Debug)]
pub enum PeerInput {
    /// Every time a STUN packages "refreshes" the connection.
    StunUpdate(Ts),
    /// Incoming UDP to be handled by the Peer, DTLS, RTP and RTCP.
    PeerUdp(PeerUdp),
    /// Subsequent SDP offers. The first SDP creates the Peer, subsequent updates the state.
    SdpOffer(Sdp, oneshot::Sender<SdpAnswer>),
    /// This oddball doesn't originate from the Server, but the DtlsStream.
    DtlsEvent(DtlsEvent),
    /// Periodical timer tick to do receiver reports.
    Periodical,
}

/// Answer to an SDP offer.
#[derive(Debug)]
pub struct SdpAnswer {
    pub sdp: Sdp,
    pub remote_creds: HashSet<IceCreds>,
}

/// UDP package intended for Peer.
#[derive(Debug)]
pub struct PeerUdp {
    pub buf: Vec<u8>,
    pub addr: SocketAddr,
    pub timestamp: Ts,
}
