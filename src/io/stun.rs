use std::fmt;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;

use crc::{Crc, CRC_32_ISO_HDLC};
use rand::random;
use thiserror::Error;

// Consult libwebrtc for default values here.
pub const STUN_INITIAL_RTO_MILLIS: u64 = 250;
pub const STUN_MAX_RETRANS: usize = 9;
pub const STUN_MAX_RTO_MILLIS: u64 = 3000;
pub const STUN_TIMEOUT: Duration = Duration::from_secs(40); // the above algo gives us 39_750

/// Calculate the send delay given how many times we tried.
///
// Technically RTO should be calculated as per https://datatracker.ietf.org/doc/html/rfc2988, and
// modified by https://datatracker.ietf.org/doc/html/rfc5389#section-7.2.1,
// but chrome does it like this. https://webrtc.googlesource.com/src/+/refs/heads/main/p2p/base/stun_request.cc
pub fn stun_resend_delay(send_count: usize) -> Duration {
    if send_count == 0 {
        return Duration::ZERO;
    }

    let retrans = (send_count - 1).min(STUN_MAX_RETRANS);

    let rto = STUN_INITIAL_RTO_MILLIS << retrans;
    let capped = rto.min(STUN_MAX_RTO_MILLIS);

    Duration::from_millis(capped)
}

/// Possible errors when handling STUN messages.
#[derive(Debug, Error)]
pub enum StunError {
    /// A STUN message could not be parsed.
    #[error("STUN parse error: {0}")]
    Parse(String),

    /// An IO error occurred while handling a STUN message.
    #[error("STUN io: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransId([u8; 12]);

impl TransId {
    pub fn new() -> Self {
        let mut t = [0_u8; 12];
        for v in &mut t {
            *v = random();
        }
        TransId(t)
    }

    fn from_slice(s: &[u8]) -> Self {
        let mut t = [0_u8; 12];
        t[..].copy_from_slice(s);
        TransId(t)
    }
}

/// Represents a STUN message as fit for our purposes.
///
/// STUN is a very flexible protocol.
/// This implementations only provides what we need for our ICE implementation.
#[derive(Clone, Copy)]
pub struct StunMessage<'a> {
    method: Method,
    class: Class,
    trans_id: TransId,
    attrs: Attributes<'a>,
    integrity: &'a [u8],
    integrity_len: u16,
}

impl<'a> StunMessage<'a> {
    /// Parse a STUN message from a slice of bytes.
    pub fn parse(buf: &[u8]) -> Result<StunMessage, StunError> {
        let typ = (buf[0] as u16 & 0b0011_1111) << 8 | buf[1] as u16;
        let len = (buf[2] as u16) << 8 | buf[3] as u16;
        if len & 0b0000_0011 > 0 {
            return Err(StunError::Parse("len is not a multiple of 4".into()));
        }
        if len as usize != buf.len() - 20 {
            return Err(StunError::Parse(
                "STUN length vs UDP packet mismatch".into(),
            ));
        }
        if &buf[4..8] != MAGIC {
            return Err(StunError::Parse("magic cookie mismatch".into()));
        }
        // typ is method and class
        // |M11|M10|M9|M8|M7|C1|M6|M5|M4|C0|M3|M2|M1|M0|
        // |11 |10 |9 |8 |7 |1 |6 |5 |4 |0 |3 |2 |1 |0 |
        let class = Class::from_typ(typ);
        let method = Method::from_typ(typ);
        let trans_id = TransId::from_slice(&buf[8..20]);

        let mut message_integrity_offset = 0;

        let attrs = Attributes::parse(&buf[20..], trans_id, &mut message_integrity_offset)?;

        // message-integrity only includes the length up until and including
        // the message-integrity attribute.
        if message_integrity_offset == 0 {
            return Err(StunError::Parse("No message integrity in incoming".into()));
        }

        // length including message integrity attribute
        let integrity_len = (message_integrity_offset + 4 + 20) as u16;

        // password as key is called "short-term credentials"
        // buffer from beginning including header (+20) to where message-integrity starts.
        let integrity = &buf[0..(message_integrity_offset + 20)];

        if method == Method::Binding && class == Class::Success {
            if attrs.xor_mapped_address.is_none() {
                return Err(StunError::Parse("STUN packet missing mapped addr".into()));
            }
        } else if method == Method::Binding && class == Class::Request {
            if attrs.split_username().is_none() {
                return Err(StunError::Parse("STUN packet missing username".into()));
            }
            if attrs.priority.is_none() {
                return Err(StunError::Parse("STUN packet missing mapped addr".into()));
            }
        }

        Ok(StunMessage {
            class,
            method,
            trans_id,
            attrs,
            integrity,
            integrity_len,
        })
    }

    /// Whether this STUN message is a BINDING request.
    pub(crate) fn is_binding_request(&self) -> bool {
        self.method == Method::Binding && self.class == Class::Request
    }

    /// Whether this STUN message is a response.
    pub(crate) fn is_response(&self) -> bool {
        matches!(self.class, Class::Success | Class::Failure)
    }

    /// Whether this STUN message is a _successful_ BINDING response.
    ///
    /// STUN binding requests are very simple, they just return the observed address.
    /// As such, they cannot actually fail which is why we don't have `is_failed_binding_response`.
    pub(crate) fn is_successful_binding_response(&self) -> bool {
        self.method == Method::Binding && self.class == Class::Success
    }

    /// The transaction ID of this STUN message.
    pub(crate) fn trans_id(&self) -> TransId {
        self.trans_id
    }

    /// Constructs a new BINDING request from the provided data.
    pub(crate) fn binding_request(
        username: &'a str,
        trans_id: TransId,
        controlling: bool,
        control_tie_breaker: u64,
        prio: u32,
        use_candidate: bool,
    ) -> Self {
        StunMessage {
            class: Class::Request,
            method: Method::Binding,
            trans_id,
            attrs: Attributes {
                username: Some(username),
                ice_controlling: controlling.then_some(control_tie_breaker),
                ice_controlled: (!controlling).then_some(control_tie_breaker),
                priority: Some(prio),
                use_candidate: use_candidate.then_some(true),
                ..Default::default()
            },
            integrity: &[],
            integrity_len: 0,
        }
    }

    /// Constructs a new STUN BINDING reply.
    pub(crate) fn reply(trans_id: TransId, mapped_address: SocketAddr) -> StunMessage<'a> {
        StunMessage {
            class: Class::Success,
            method: Method::Binding,
            trans_id,
            attrs: Attributes {
                xor_mapped_address: Some(mapped_address),
                ..Default::default()
            },
            integrity: &[],
            integrity_len: 0,
        }
    }

    /// If present, splits the value of the USERNAME attribute into local and remote (separated by `:`).
    pub(crate) fn split_username(&self) -> Option<(&str, &str)> {
        self.attrs.split_username()
    }

    /// If present, returns the value of XOR-MAPPED-ADDRESS attribute.
    pub(crate) fn mapped_address(&self) -> Option<SocketAddr> {
        self.attrs.xor_mapped_address
    }

    /// If present, returns the value of the PRIORITY attribute.
    pub(crate) fn prio(&self) -> Option<u32> {
        self.attrs.priority
    }

    /// Whether this message has the USE-CANDIDATE attribute.
    pub(crate) fn use_candidate(&self) -> bool {
        self.attrs.use_candidate()
    }

    /// Verify the integrity of this message against the provided password.
    #[must_use]
    pub(crate) fn check_integrity(&self, password: &str) -> bool {
        if let Some(integ) = self.attrs.message_integrity {
            let sha1: Sha1 = password.as_bytes().into();
            let comp = sha1.hmac(&[
                &self.integrity[..2],
                &[(self.integrity_len >> 8) as u8, self.integrity_len as u8],
                &self.integrity[4..],
            ]);
            comp == integ
        } else {
            false
        }
    }

    /// Serialize this message into the provided buffer, returning the final length of the message.
    ///
    /// The provided password is used to authenticate the message.
    pub(crate) fn to_bytes(self, password: &str, buf: &mut [u8]) -> Result<usize, StunError> {
        const MSG_HEADER_LEN: usize = 20;
        const MSG_INTEGRITY_LEN: usize = 20;
        const FPRINT_LEN: usize = 4;
        const ATTR_TLV_LENGTH: usize = 4;

        let attr_len = self.attrs.padded_len()
            + MSG_INTEGRITY_LEN
            + ATTR_TLV_LENGTH
            + FPRINT_LEN
            + ATTR_TLV_LENGTH;

        let mut buf = io::Cursor::new(buf);

        // Message header
        {
            let typ = self.class.to_u16() | self.method.to_u16();
            buf.write_all(&typ.to_be_bytes())?;

            // -8 for fingerprint
            buf.write_all(&((attr_len - 8) as u16).to_be_bytes())?;
            buf.write_all(MAGIC)?;
            buf.write_all(&self.trans_id.0)?;
        }

        // Custom attributes
        self.attrs.to_bytes(&mut buf, &self.trans_id.0)?;

        // Message integrity
        buf.write_all(&0x0008_u16.to_be_bytes())?;
        buf.write_all(&(MSG_INTEGRITY_LEN as u16).to_be_bytes())?;
        buf.write_all(&[0; MSG_INTEGRITY_LEN])?; // placeholder
        let integrity_value_offset = MSG_HEADER_LEN + self.attrs.padded_len() + ATTR_TLV_LENGTH;

        // Fingerprint
        buf.write_all(&0x8028_u16.to_be_bytes())?;
        buf.write_all(&(FPRINT_LEN as u16).to_be_bytes())?;
        buf.write_all(&[0; FPRINT_LEN])?; // placeholder
        let fingerprint_value_offest = integrity_value_offset + MSG_INTEGRITY_LEN + ATTR_TLV_LENGTH;

        let buf = buf.into_inner();

        // Compute and fill in message integrity
        let sha1: Sha1 = password.as_bytes().into();
        let hmac = sha1.hmac(&[&buf[0..(integrity_value_offset - ATTR_TLV_LENGTH)]]);
        buf[integrity_value_offset..(integrity_value_offset + MSG_INTEGRITY_LEN)]
            .copy_from_slice(&hmac);

        // Fill in total message length
        buf[2..4].copy_from_slice(&(attr_len as u16).to_be_bytes());

        // Compute and fill in fingerprint
        let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC)
            .checksum(&buf[0..(fingerprint_value_offest - ATTR_TLV_LENGTH)])
            ^ 0x5354_554e;
        buf[fingerprint_value_offest..(fingerprint_value_offest + FPRINT_LEN)]
            .copy_from_slice(&crc.to_be_bytes());

        Ok(MSG_HEADER_LEN + attr_len)
    }
}

const MAGIC: &[u8] = &[0x21, 0x12, 0xA4, 0x42];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Class {
    Request,
    Indication,
    Success,
    Failure,
    Unknown,
}

impl Class {
    fn from_typ(typ: u16) -> Self {
        use Class::*;
        match typ & 0b0000_0001_0001_0000 {
            0b0000_0000_0000_0000 => Request,
            0b0000_0000_0001_0000 => Indication,
            0b0000_0001_0000_0000 => Success,
            0b0000_0001_0001_0000 => Failure,
            _ => Unknown,
        }
    }

    fn to_u16(self) -> u16 {
        use Class::*;
        match self {
            Request => 0b0000_0000_0000_0000,
            Indication => 0b0000_0000_0001_0000,
            Success => 0b0000_0001_0000_0000,
            Failure => 0b0000_0001_0001_0000,
            _ => panic!("Unknown class"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Method {
    Binding,
    Unknown,
}

impl Method {
    fn from_typ(typ: u16) -> Self {
        use Method::*;
        match typ & 0b0011_1110_1110_1111 {
            0b0000_0000_0000_0001 => Binding,
            _ => Unknown,
        }
    }

    fn to_u16(self) -> u16 {
        use Method::*;
        match self {
            Binding => 0b0000_0000_0000_0001,
            _ => panic!("Unknown method"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attributes<'a> {
    username: Option<&'a str>,              // < 128 utf8 chars
    message_integrity: Option<&'a [u8]>,    // 20 bytes sha-1
    error_code: Option<(u16, &'a str)>,     // 300-699 and reason phrase < 128 utf8 chars
    realm: Option<&'a str>,                 // < 128 utf8 chars
    nonce: Option<&'a str>,                 // < 128 utf8 chars
    xor_mapped_address: Option<SocketAddr>, // 0x0020
    software: Option<&'a str>,
    fingerprint: Option<u32>, // crc32
    // https://tools.ietf.org/html/rfc8445
    priority: Option<u32>,        // 0x0024
    use_candidate: Option<bool>,  // 0x0025
    ice_controlled: Option<u64>,  // 0x8029
    ice_controlling: Option<u64>, // 0x802a
    // https://tools.ietf.org/html/draft-thatcher-ice-network-cost-00
    network_cost: Option<(u16, u16)>, // 0xc057
                                      // Unknown: u16,
}

impl<'a> Attributes<'a> {
    fn split_username(&self) -> Option<(&'a str, &'a str)> {
        // usernames are on the form gfNK:062g where
        // gfNK is my local sdp ice username and
        // 062g is the remote.

        let v = self.username?;
        let idx = v.find(':')?;

        if idx + 1 >= v.len() {
            return None;
        }

        let local = &v[..idx];
        let remote = &v[(idx + 1)..];

        Some((local, remote))
    }

    fn use_candidate(&self) -> bool {
        self.use_candidate.unwrap_or(false)
    }
}

use std::{io, str};

use super::Sha1;

impl<'a> Attributes<'a> {
    fn padded_len(&self) -> usize {
        let username = self
            .username
            .map(|v| {
                let pad = 4 - (v.as_bytes().len() % 4) % 4;
                4 + v.len() + pad
            })
            .unwrap_or_default();
        let ice_controlled = self.ice_controlled.map(|_| 4 + 8).unwrap_or_default();
        let ice_controlling = self.ice_controlling.map(|_| 4 + 8).unwrap_or_default();
        let priority = self
            .priority
            .map(|p| 4 + p.to_le_bytes().len())
            .unwrap_or_default();
        let address = self
            .xor_mapped_address
            .map(|a| 4 + if a.is_ipv4() { 8 } else { 20 })
            .unwrap_or_default();
        let use_candidate = self.use_candidate.map(|_| 4).unwrap_or_default();

        username + ice_controlled + ice_controlling + priority + address + use_candidate
    }

    fn to_bytes(self, vec: &mut dyn Write, trans_id: &[u8]) -> io::Result<()> {
        if let Some(v) = self.username {
            vec.write_all(&0x0006_u16.to_be_bytes())?;
            vec.write_all(&(v.as_bytes().len() as u16).to_be_bytes())?;
            vec.write_all(v.as_bytes())?;
            let pad = 4 - (v.as_bytes().len() % 4) % 4;
            for _ in 0..pad {
                vec.write_all(&[0])?;
            }
        }
        if let Some(v) = self.ice_controlled {
            vec.write_all(&0x8029_u16.to_be_bytes())?;
            vec.write_all(&8_u16.to_be_bytes())?;
            vec.write_all(&v.to_be_bytes())?;
        }
        if let Some(v) = self.ice_controlling {
            vec.write_all(&0x802a_u16.to_be_bytes())?;
            vec.write_all(&8_u16.to_be_bytes())?;
            vec.write_all(&v.to_be_bytes())?;
        }
        if let Some(v) = self.priority {
            vec.write_all(&0x0024_u16.to_be_bytes())?;
            vec.write_all(&4_u16.to_be_bytes())?;
            vec.write_all(&v.to_be_bytes())?;
        }
        if let Some(v) = self.xor_mapped_address {
            let mut buf = [0_u8; 20];
            let len = encode_xor(v, &mut buf, trans_id);
            vec.write_all(&0x0020_u16.to_be_bytes())?;
            vec.write_all(&((len as u16).to_be_bytes()))?;
            vec.write_all(&buf[0..len])?;
        }
        if self.use_candidate() {
            vec.write_all(&0x0025_u16.to_be_bytes())?;
            vec.write_all(&0_u16.to_be_bytes())?;
        }

        Ok(())
    }

    fn parse(
        mut buf: &'a [u8],
        trans_id: TransId,
        msg_integrity_off: &mut usize,
    ) -> Result<Attributes<'a>, StunError> {
        let mut attributes = Attributes::default();

        let mut off = 0;
        // With the exception of the FINGERPRINT
        //    attribute, which appears after MESSAGE-INTEGRITY, agents MUST ignore
        //    all other attributes that follow MESSAGE-INTEGRITY
        let mut ignore_rest = false;
        loop {
            if buf.is_empty() {
                break;
            }
            let typ = (buf[0] as u16) << 8 | buf[1] as u16;
            let len = (buf[2] as usize) << 8 | buf[3] as usize;
            trace!(
                "STUN attribute typ 0x{:04x?} len {}: {:02x?}",
                typ,
                len,
                buf
            );
            if len > buf.len() - 4 {
                return Err(StunError::Parse(format!(
                    "Bad STUN attribute length: {} > {}",
                    len,
                    buf.len() - 4,
                )));
            }
            if !ignore_rest || typ == 0x8028 {
                match typ {
                    0x0001 => {
                        warn!("STUN got MappedAddress");
                    }
                    0x0006 => {
                        attributes.username = Some(decode_str(typ, &buf[4..], len)?);
                    }
                    0x0008 => {
                        if len != 20 {
                            return Err(StunError::Parse(
                                "Expected message integrity to have length 20".into(),
                            ));
                        }
                        // message integrity is up until, but not including the message
                        // integrity attribute.
                        *msg_integrity_off = off;
                        ignore_rest = true;
                        attributes.message_integrity = Some(&buf[4..24]);
                    }
                    0x0009 => {
                        if buf[4] != 0 || buf[5] != 0 || buf[6] & 0b1111_1000 != 0 {
                            return Err(StunError::Parse("Expected 0 at top of error code".into()));
                        }
                        let class = buf[6] as u16 * 100;
                        if class < 300 || class > 699 {
                            return Err(StunError::Parse(format!(
                                "Error class is not in range: {class}"
                            )));
                        }
                        let code = class + (buf[7] % 100) as u16;
                        attributes.error_code = Some((code, decode_str(typ, &buf[8..], len - 4)?));
                    }
                    0x000a => {
                        warn!("STUN got UnknownAttributes");
                    }
                    0x0014 => {
                        attributes.realm = Some(decode_str(typ, &buf[4..], len)?);
                    }
                    0x0015 => {
                        attributes.nonce = Some(decode_str(typ, &buf[4..], len)?);
                    }
                    0x0020 => {
                        attributes.xor_mapped_address = Some(decode_xor(&buf[4..], trans_id)?);
                    }
                    0x0022 => {
                        attributes.software = Some(decode_str(typ, &buf[4..], len)?);
                    }
                    0x0024 => {
                        if len != 4 {
                            return Err(StunError::Parse("Priority that isnt 4 in length".into()));
                        }
                        let bytes = [buf[4], buf[5], buf[6], buf[7]];
                        attributes.priority = Some(u32::from_be_bytes(bytes));
                    }
                    0x0025 => {
                        if len != 0 {
                            return Err(StunError::Parse(
                                "UseCandidate that isnt 0 in length".into(),
                            ));
                        }
                        attributes.use_candidate = Some(true);
                    }
                    0x8023 => {
                        warn!("STUN got AlternateServer");
                    }
                    0x8028 => {
                        let bytes = [buf[4], buf[5], buf[6], buf[7]];
                        attributes.fingerprint = Some(u32::from_be_bytes(bytes));
                    }
                    0x8029 => {
                        if len != 8 {
                            return Err(StunError::Parse(
                                "IceControlled that isnt 8 in length".into(),
                            ));
                        }
                        let mut bytes = [0_u8; 8];
                        bytes.copy_from_slice(&buf[4..(4 + 8)]);
                        attributes.ice_controlled = Some(u64::from_be_bytes(bytes));
                    }
                    0x802a => {
                        if len != 8 {
                            return Err(StunError::Parse(
                                "IceControlling that isnt 8 in length".into(),
                            ));
                        }
                        let mut bytes = [0_u8; 8];
                        bytes.copy_from_slice(&buf[4..(4 + 8)]);
                        attributes.ice_controlling = Some(u64::from_be_bytes(bytes));
                    }
                    0xc057 => {
                        if len != 4 {
                            warn!("NetworkCost that isnt 4 in length");
                        } else {
                            let net_id = (buf[4] as u16) << 8 | buf[5] as u16;
                            let cost = (buf[6] as u16) << 8 | buf[7] as u16;
                            attributes.network_cost = Some((net_id, cost));
                        }
                    }
                    _ => {}
                }
            }
            // attributes are on even 32 bit boundaries
            let pad = (4 - (len % 4)) % 4;
            let pad_len = len + pad;
            buf = &buf[(4 + pad_len)..];
            off += 4 + pad_len;
        }
        Ok(attributes)
    }
}

fn decode_str(typ: u16, buf: &[u8], len: usize) -> Result<&str, StunError> {
    if len > 128 {
        return Err(StunError::Parse(format!(
            "0x{typ:04x?} too long str len: {len}"
        )));
    }
    match str::from_utf8(&buf[0..len]).ok() {
        Some(v) => Ok(v),
        None => Err(StunError::Parse(format!("0x{typ:04x?} malformed utf-8"))),
    }
}

fn encode_xor(addr: SocketAddr, buf: &mut [u8; 20], trans_id: &[u8]) -> usize {
    let port = addr.port() ^ 0x2112;
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[1] = if addr.is_ipv4() { 1 } else { 2 };
    let ip_buf = &mut buf[4..];
    match addr {
        SocketAddr::V4(v) => {
            let bytes = v.ip().octets();
            for i in 0..4 {
                ip_buf[i] = bytes[i] ^ MAGIC[i];
            }
            8
        }
        SocketAddr::V6(v) => {
            let bytes = v.ip().octets();
            for i in 0..4 {
                ip_buf[i] = bytes[i] ^ MAGIC[i];
            }
            for i in 4..16 {
                ip_buf[i] = bytes[i] ^ trans_id[i - 4];
            }
            20
        }
    }
}

fn decode_xor(buf: &[u8], trans_id: TransId) -> Result<SocketAddr, StunError> {
    let port = (((buf[2] as u16) << 8) | (buf[3] as u16)) ^ 0x2112;
    let ip_buf = &buf[4..];
    let ip = match buf[1] {
        1 => {
            let mut bytes = [0_u8; 4];
            for i in 0..4 {
                bytes[i] = ip_buf[i] ^ MAGIC[i];
            }
            IpAddr::V4(bytes.into())
        }
        2 => {
            let mut bytes = [0_u8; 16];
            for i in 0..4 {
                bytes[i] = ip_buf[i] ^ MAGIC[i];
            }
            for i in 4..16 {
                bytes[i] = ip_buf[i] ^ trans_id.0[i - 4];
            }
            IpAddr::V6(bytes.into())
        }
        e => {
            return Err(StunError::Parse(format!("Invalid address family: {e:?}")));
        }
    };

    Ok(SocketAddr::new(ip, port))
}

impl<'a> fmt::Debug for StunMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StunMessage")
            .field("method", &self.method)
            .field("class", &self.class)
            .field("attrs", &self.attrs)
            .field("integrity_len", &self.integrity.len())
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_stun_message() {
        const PACKET: &[u8] = &[
            0x00, 0x01, 0x00, 0x50, 0x21, 0x12, 0xa4, 0x42, 0x6a, 0x75, 0x63, 0x31, 0x35, 0x75,
            0x78, 0x55, 0x6e, 0x67, 0x47, 0x63, 0x00, 0x06, 0x00, 0x09, 0x70, 0x39, 0x4b, 0x41,
            0x3a, 0x53, 0x51, 0x41, 0x74, 0x00, 0x00, 0x00, 0xc0, 0x57, 0x00, 0x04, 0x00, 0x01,
            0x00, 0x0a, 0x80, 0x2a, 0x00, 0x08, 0x6e, 0xee, 0xc6, 0xe9, 0x7d, 0x18, 0x39, 0x5c,
            0x00, 0x25, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x7f, 0x1e, 0xff, 0x00, 0x08,
            0x00, 0x14, 0x5d, 0x04, 0x25, 0xa0, 0x20, 0x7a, 0xb1, 0xe0, 0x54, 0x10, 0x22, 0x99,
            0xaa, 0xf9, 0x83, 0x9c, 0xa0, 0x76, 0xc6, 0xd5, 0x80, 0x28, 0x00, 0x04, 0x36, 0x0e,
            0x21, 0x9f,
        ];

        let packet = PACKET.to_vec();
        let message = StunMessage::parse(&packet).unwrap();
        assert!(message.check_integrity("xJcE9AQAR7kczUDVOXRUCl"));
    }
}
