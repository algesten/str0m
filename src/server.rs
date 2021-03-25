use crate::peer::{Peer, PeerHandle, PeerInput, PeerUdp};
use crate::rt::{mpsc, oneshot, spawn, UdpSocket};
use crate::sdp::{Candidate, Sdp};
use crate::sdp_parse::parse_sdp;
use crate::stun;
use crate::util::Ts;
use crate::Error;
use crate::{JoinReq, JoinResp};
use std::net::SocketAddr;
use std::sync::Arc;

pub struct Server {
    candidates: Vec<Candidate>,
    peers: Vec<PeerHandle>,
    rx: ServerIn,
    tx: ServerOut,
}

pub struct ServerIn {
    pub udp: Arc<UdpSocket>,
    pub signal: mpsc::Receiver<SignalIn>,
}

#[derive(Debug, Clone)]
pub struct ServerOut {
    pub udp: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

#[derive(Debug)]
pub enum SignalIn {
    JoinReq(JoinReq, oneshot::Sender<JoinResp>),
    // Remove(SessionId),
}

impl Server {
    pub fn new(candidates: Vec<Candidate>, rx: ServerIn, tx: ServerOut) -> Self {
        Server {
            candidates,
            peers: vec![],
            rx,
            tx,
        }
    }

    pub async fn handle(&mut self) {
        loop {
            let mut udp_buf = vec![0_u8; 2000];
            crate::rt::select! {
                v = self.rx.signal.recv() => {
                    let timestamp = Ts::now();
                    if let Some(v) = v {
                        self.handle_signal_in(v, timestamp).await;
                    } else {
                        //
                        break;
                    }
                },
                v = self.rx.udp.recv_from(&mut udp_buf[..]) => {
                    let timestamp = Ts::now();
                    match v {
                        Ok(v) => {
                            let (n, addr) = v;
                            udp_buf.truncate(n);
                            self.handle_udp(udp_buf, addr, timestamp).await;
                        },
                        Err(e) => {
                            warn!("UDP Error: {:?}", e);
                            break;
                        }
                    }
                },
            }
        }
    }

    async fn handle_signal_in(&mut self, oper: SignalIn, timestamp: Ts) {
        match oper {
            SignalIn::JoinReq(req, tx) => {
                self.handle_join_req(req, tx, timestamp)
                    .await
                    .expect("handle_join_req");
            } // SignalIn::Remove(sid) => {
              //     self.peers.retain(|p| p.local_id != sid);
              // }
        }
    }

    async fn handle_join_req(
        &mut self,
        req: JoinReq,
        tx_join: oneshot::Sender<JoinResp>,
        timestamp: Ts,
    ) -> Result<(), Error> {
        let sdp = parse_sdp(&req.sdp)?;
        let remote_id = &sdp.session.id;
        let existing = self.peers.iter_mut().find(|p| p.remote_id == *remote_id);

        if let Some(peer) = existing {
            peer.last_used = timestamp;

            let (tx_sdp, rx_sdp) = oneshot::channel();

            // send off to peer handler
            peer.tx
                .send(PeerInput::SdpOffer(sdp, tx_sdp))
                .await
                .expect("peer.tx.send sdp offer");
            let answer = rx_sdp.await.expect("rx_sdp");

            // update the creds since they might have changed
            peer.remote_creds = answer.remote_creds;
            trace!("Updated remote creds: {:?}", peer.remote_creds);

            // answer back to caller
            tx_join
                .send(JoinResp {
                    sdp: answer.sdp.to_string(),
                })
                .ok();
        } else {
            self.handle_new_peer(sdp, tx_join)?;
        }
        Ok(())
    }

    fn handle_new_peer(
        &mut self,
        remote_sdp: Sdp,
        tx_join: oneshot::Sender<JoinResp>,
    ) -> Result<(), Error> {
        info!("JOIN new peer: {:?}", remote_sdp.session.id);

        let tx_server = self.tx.clone();
        let mut peer = Peer::new(&self.candidates, tx_server);
        peer.apply_remote_sdp(&remote_sdp)?;

        // add remote input to this peer
        self.peers.push(peer.handle());

        let answer = peer.create_local_sdp();
        tx_join
            .send(JoinResp {
                sdp: answer.to_string(),
            })
            .ok();

        spawn(async move {
            peer.peer_main_loop().await;
        });

        Ok(())
    }

    async fn handle_udp(&mut self, buf: Vec<u8>, addr: SocketAddr, timestamp: Ts) {
        let kind = buf.udp_kind();
        // trace!("UDP RECV {:?} ({}): {:?}", kind, addr, buf.disp());
        match kind {
            UdpKind::Stun => {
                self.handle_stun(buf, addr, timestamp).await;
            }
            UdpKind::Dtls | UdpKind::Rtcp | UdpKind::Rtp => {
                let peer = self.peer_by_verified_addr(&addr);

                if let Some(peer) = peer {
                    peer.last_used = timestamp;

                    let pudp = PeerUdp {
                        buf,
                        addr,
                        timestamp,
                    };

                    peer.tx.send(PeerInput::PeerUdp(pudp)).await.ok();
                } else {
                    trace!("UDP RECV non-verified ({}): {:?}", addr, buf.disp());
                }
            }
            UdpKind::Unknown => {
                // drop
            }
        }
    }

    async fn handle_stun(
        &mut self,
        mut buf: Vec<u8>,
        addr: SocketAddr,
        timestamp: Ts,
    ) -> Option<()> {
        let pkt = stun::parse_message(&mut buf[..])?;
        let (local_username, remote_username) = pkt.local_remote_username()?;

        let peer = self.peer_by_username(remote_username)?;

        let creds = &peer.local.ice_creds;

        if local_username != creds.username {
            trace!(
                "STUN local != peer.local ({}): {} != {}",
                addr,
                local_username,
                creds.username
            );
            return None;
        }
        if !pkt.check_integrity(&creds.password) {
            trace!("STUN check_integrity failed ({})", addr,);
            return None;
        }

        let reply = pkt.reply()?;
        let bytes = reply.to_bytes(&creds.password);

        // if this fails, the peer has disappeared.
        if peer
            .tx
            .send(PeerInput::StunUpdate(timestamp))
            .await
            .is_err()
        {
            drop(peer);
            self.remove_verified_peer(&addr);
            return None;
        }

        // on the back of a successful (authenticated) stun bind, we update
        // the validated addresses to receive dtls, rtcp, rtp etc.
        if peer.verified.insert(addr) {
            trace!("STUN new verified peer ({})", addr);
        }

        let pkt = (bytes, addr);
        self.tx
            .udp
            .send(pkt)
            .await
            .expect("tx.upd.send stun response");

        Some(())
    }

    fn peer_by_username(&mut self, username: &str) -> Option<&mut PeerHandle> {
        for peer in &mut self.peers {
            for creds in &peer.remote_creds {
                if creds.username == username {
                    return Some(peer);
                }
            }
        }
        None
    }

    fn peer_by_verified_addr(&mut self, addr: &SocketAddr) -> Option<&mut PeerHandle> {
        for peer in &mut self.peers {
            if peer.verified.contains(addr) {
                return Some(peer);
            }
        }
        None
    }

    fn remove_verified_peer(&mut self, addr: &SocketAddr) {
        trace!("Remove peer: {}", addr);
        self.peers.retain(|p| !p.verified.contains(addr));
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UdpKind {
    Stun,
    Dtls,
    Rtp,
    Rtcp,
    Unknown,
}

pub trait BufExt {
    fn udp_kind(&self) -> UdpKind;
    fn disp(&self) -> &[u8];
}

impl BufExt for Vec<u8> {
    fn udp_kind(&self) -> UdpKind {
        let byte0 = self[0];
        if byte0 < 2 && self.len() >= 20 {
            UdpKind::Stun
        } else if byte0 >= 20 && byte0 < 64 {
            UdpKind::Dtls
        } else if byte0 >= 128 && byte0 < 192 && self.len() > 2 {
            let pt = self[1] & 0x7f;
            if pt >= 64 && pt < 96 {
                UdpKind::Rtcp
            } else {
                UdpKind::Rtp
            }
        } else {
            UdpKind::Unknown
        }
    }
    fn disp(&self) -> &[u8] {
        let max = self.len().min(8);
        &self[0..max]
    }
}

pub struct UdpSend(
    pub mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    pub Arc<UdpSocket>,
);
impl UdpSend {
    pub async fn handle(&mut self) {
        loop {
            let (buf, addr) = self.0.recv().await.unwrap();
            // debug!("UDP SEND ({}): {:02x?} {}", addr, buf.disp(), buf.len());
            if let Err(e) = self.1.send_to(&buf, &addr).await {
                warn!("Failed to send UDP: {}", e);
                break;
            }
        }
    }
}
