use std::collections::HashSet;
use std::net::SocketAddr;

use crate::peer::OutputQueue;
use crate::sdp::{IceCreds, SessionId};
use crate::stun::StunMessage;
use crate::util::random_id;
use crate::Error;

pub(crate) struct IceState {
    /// Local credentials for STUN. We use one set for all m-lines.
    local_creds: IceCreds,

    /// Remote credentials for STUN. Obtained from SDP.
    remote_creds: HashSet<IceCreds>,

    /// Addresses that have been "unlocked" via STUN. These IP:PORT combos
    /// are now verified for other kinds of data like DTLS, RTP, RTCP...
    verified: HashSet<SocketAddr>,
}

impl IceState {
    pub fn new() -> Self {
        IceState {
            local_creds: IceCreds {
                username: random_id::<8>().to_string(),
                password: random_id::<24>().to_string(),
            },
            remote_creds: HashSet::new(),
            verified: HashSet::new(),
        }
    }

    pub fn add_remote_creds(&mut self, id: &SessionId, creds: IceCreds) {
        let line = format!("{:?} Added remote creds: {:?}", id, creds);
        if self.remote_creds.insert(creds) {
            trace!(line);
        }
    }

    pub fn accepts_stun(&self, addr: SocketAddr, stun: &StunMessage<'_>) -> Result<bool, Error> {
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

    pub fn handle_stun<'a>(
        &mut self,
        addr: SocketAddr,
        output: &mut OutputQueue,
        stun: StunMessage<'a>,
    ) -> Result<(), Error> {
        let reply = stun.reply()?;

        // on the back of a successful (authenticated) stun bind, we update
        // the validated addresses to receive dtls, rtcp, rtp etc.
        if self.verified.insert(addr) {
            trace!("STUN new verified peer ({})", addr);
        }

        let mut writer = output.get_buffer_writer();
        let len = reply.to_bytes(&self.local_creds.password, &mut writer)?;
        let buffer = writer.set_len(len);

        output.enqueue(addr, buffer);

        Ok(())
    }

    pub fn is_stun_verified(&self, addr: SocketAddr) -> bool {
        self.verified.contains(&addr)
    }

    pub fn has_any_verified(&self) -> bool {
        !self.verified.is_empty()
    }

    pub fn local_creds(&self) -> &IceCreds {
        &self.local_creds
    }
}
