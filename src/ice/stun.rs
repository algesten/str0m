use crc::{Crc, CRC_32_ISO_HDLC};
use hmac::Hmac;
use hmac::Mac;
use hmac::NewMac;
use rand::prelude::*;
use sha1::Sha1;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

// Consult libwebrtc for default values here.
pub const STUN_INITIAL_RTO_MILLIS: u64 = 250;
pub const STUN_MAX_RETRANS: usize = 9;
pub const STUN_MAX_RTO_MILLIS: u64 = 8000;
pub const STUN_TIMEOUT: Duration = Duration::from_secs(40); // the above algo gives us 39_750

/// Calculate the send delay given how many times we tried.
///
/// Technically RTO should be calculated as per https://datatracker.ietf.org/doc/html/rfc2988, and
/// modified by https://datatracker.ietf.org/doc/html/rfc5389#section-7.2.1,
/// but chrome does it like this. https://webrtc.googlesource.com/src/+/refs/heads/main/p2p/base/stun_request.cc
pub fn stun_resend_delay(send_count: usize) -> Duration {
    if send_count == 0 {
        return Duration::ZERO;
    }

    let retrans = (send_count - 1).min(STUN_MAX_RETRANS);

    let rto = STUN_INITIAL_RTO_MILLIS << retrans;
    let capped = rto.min(STUN_MAX_RTO_MILLIS);

    Duration::from_millis(capped)
}

#[derive(Debug, Error)]
pub enum StunError {
    #[error("STUN parse error: {0}")]
    Parse(String),

    #[error("STUN io: {0}")]
    Io(#[from] io::Error),

    #[error("STUN error: {0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub struct StunMessage<'a> {
    class: Class,
    method: Method,
    trans_id: &'a [u8],
    attrs: Vec<Attribute<'a>>,
    integrity: &'a [u8],
}

impl<'a> StunMessage<'a> {
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
        let begin = &buf[0..4];
        // let buf_ptr = buf as *mut [u8];
        let trans_id = &buf[8..20];

        let mut message_integrity_offset = 0;

        let attrs = Attribute::parse(&buf[20..], trans_id, &mut message_integrity_offset)?;

        // message-integrity only includes the length up until and including
        // the message-integrity attribute.
        if message_integrity_offset == 0 {
            return Err(StunError::Parse("No message integrity in incoming".into()));
        }

        // length including message integrity attribute
        let m_int_len = (message_integrity_offset + 4 + 20) as u16;

        // this is safe because Attribute::parse() hasn't borrowed this part.
        unsafe {
            let ptr = begin as *const [u8] as *mut [u8];
            (*ptr)[2] = (m_int_len >> 8) as u8;
            (*ptr)[3] = m_int_len as u8;
        }

        // password as key is called "short-term credentials"
        // buffer from beginning including header (+20) to where message-integrity starts.
        let integrity = &buf[0..(message_integrity_offset + 20)];

        if attrs.split_username().is_none() {
            return Err(StunError::Parse("STUN packet missing username".into()));
        }

        if method == Method::Binding && class == Class::Success {
            if attrs.mapped_address().is_none() {
                return Err(StunError::Parse("STUN packet missing mapped addr".into()));
            }
        } else if method == Method::Binding && class == Class::Request {
            if attrs.prio().is_none() {
                return Err(StunError::Parse("STUN packet missing mapped addr".into()));
            }
        }

        Ok(StunMessage {
            class,
            method,
            trans_id,
            attrs,
            integrity,
        })
    }

    pub fn is_binding_request(&self) -> bool {
        self.method == Method::Binding && self.class == Class::Request
    }

    pub fn is_successful_binding_response(&self) -> bool {
        self.method == Method::Binding && self.class == Class::Success
    }

    pub fn trans_id(&self) -> &[u8] {
        self.trans_id
    }

    pub fn binding_request(
        username: &'a str,
        trans_id: &'a [u8; 12],
        controlling: bool,
        prio: u32,
        use_candidate: bool,
    ) -> Self {
        let mut m = StunMessage {
            class: Class::Request,
            method: Method::Binding,
            trans_id: &*trans_id,
            attrs: vec![
                Attribute::Username(username),
                if controlling {
                    Attribute::IceControlling(random())
                } else {
                    Attribute::IceControlled(random())
                },
                Attribute::Priority(prio),
            ],
            integrity: &[],
        };

        if use_candidate {
            m.attrs.push(Attribute::UseCandidate);
        }

        m.attrs.push(Attribute::MessageIntegrityMark);
        m.attrs.push(Attribute::FingerprintMark);

        m
    }

    pub fn reply(
        username: &'a str,
        trans_id: &'a [u8; 12],
        mapped_address: SocketAddr,
    ) -> StunMessage<'a> {
        StunMessage {
            class: Class::Success,
            method: Method::Binding,
            trans_id,
            attrs: vec![
                Attribute::Username(username),
                Attribute::XorMappedAddress(mapped_address),
                Attribute::MessageIntegrityMark,
                Attribute::FingerprintMark,
            ],
            integrity: &[],
        }
    }

    pub fn split_username(&self) -> (&str, &str) {
        // The existance of this is attribute checked in the parsing.
        self.attrs.split_username().unwrap()
    }

    pub fn mapped_address(&self) -> Option<SocketAddr> {
        self.attrs.mapped_address()
    }

    pub fn prio(&self) -> Option<u32> {
        self.attrs.prio()
    }

    pub fn use_candidate(&self) -> bool {
        self.attrs.use_candidate()
    }

    pub fn check_integrity(&self, password: &str) -> bool {
        if let Some(integ) = self.attrs.message_integrity() {
            let comp = hmac_sha1(password.as_bytes(), self.integrity);
            comp == integ
        } else {
            false
        }
    }

    pub fn to_bytes(&self, password: &str, buf: &mut [u8]) -> Result<usize, StunError> {
        Ok(self
            .do_to_bytes(password, buf)
            .map_err(|e| StunError::Other(format!("io write: {:?}", e)))?)
    }

    fn do_to_bytes(&self, password: &str, buf: &mut [u8]) -> Result<usize, io::Error> {
        let attr_len = self.attrs.iter().fold(0, |p, a| p + a.padded_len());
        let msg_len = 20 + attr_len;

        let mut buf = io::Cursor::new(buf);

        let typ = self.class.to_u16() | self.method.to_u16();
        buf.write_all(&typ.to_be_bytes())?;

        // -8 for fingerprint
        buf.write_all(&((attr_len - 8) as u16).to_be_bytes())?;
        buf.write_all(MAGIC)?;
        buf.write_all(self.trans_id)?;

        let mut i_off = 0;
        let mut f_off = 0;

        {
            let mut off = 20; // attribute start
            for a in &self.attrs {
                a.to_bytes(&mut buf, self.trans_id)?;
                if let Attribute::MessageIntegrityMark = a {
                    i_off = off;
                }
                if let Attribute::FingerprintMark = a {
                    f_off = off;
                }
                off += a.padded_len();
            }
        }

        let buf = buf.into_inner();

        let hmac = hmac_sha1(password.as_bytes(), &buf[0..i_off]);
        (&mut buf[i_off + 4..(i_off + 4 + 20)]).copy_from_slice(&hmac);

        // fill in correct length
        (&mut buf[2..4]).copy_from_slice(&(attr_len as u16).to_be_bytes());

        let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(&buf[0..f_off]) ^ 0x5354_554e;
        (&mut buf[f_off + 4..(f_off + 4 + 4)]).copy_from_slice(&crc.to_be_bytes());

        Ok(msg_len)
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

#[derive(Clone, Debug, PartialEq)]
pub enum Attribute<'a> {
    MappedAddress,              // TODO
    Username(&'a str),          // < 128 utf8 chars
    MessageIntegrity(&'a [u8]), // 20 bytes sha-1
    MessageIntegrityMark,       // 20 bytes sha-1
    ErrorCode(u16, &'a str),    // 300-699 and reason phrase < 128 utf8 chars
    UnknownAttributes,          // TODO
    Realm(&'a str),             // < 128 utf8 chars
    Nonce(&'a str),             // < 128 utf8 chars
    XorMappedAddress(SocketAddr),
    Software(&'a str),
    AlternateServer,  // TODO
    Fingerprint(u32), // crc32
    FingerprintMark,  // crc32
    // https://tools.ietf.org/html/rfc8445
    Priority(u32),       // 0x0024
    UseCandidate,        // 0x0025
    IceControlled(u64),  // 0x8029
    IceControlling(u64), // 0x802a
    // https://tools.ietf.org/html/draft-thatcher-ice-network-cost-00
    NetworkCost(u16, u16), // 0xc057
    Unknown(u16),
}

trait Attributes<'a> {
    fn username(&self) -> Option<&'a str>;
    fn split_username(&self) -> Option<(&'a str, &'a str)>;
    fn mapped_address(&self) -> Option<SocketAddr>;
    fn prio(&self) -> Option<u32>;
    fn use_candidate(&self) -> bool;
    fn message_integrity(&self) -> Option<&'a [u8]>;
}

impl<'a> Attributes<'a> for Vec<Attribute<'a>> {
    fn username(&self) -> Option<&'a str> {
        for a in self {
            if let Attribute::Username(v) = a {
                return Some(v);
            }
        }
        None
    }

    fn split_username(&self) -> Option<(&'a str, &'a str)> {
        // usernames are on the form gfNK:062g where
        // gfNK is my local sdp ice username and
        // 062g is the remote.
        if let Some(v) = self.username() {
            let idx = v.find(':');
            if let Some(idx) = idx {
                if idx + 1 < v.len() {
                    let local = &v[..idx];
                    let remote = &v[(idx + 1)..];
                    return Some((local, remote));
                }
            }
        }
        None
    }

    fn mapped_address(&self) -> Option<SocketAddr> {
        for a in self {
            if let Attribute::XorMappedAddress(v) = a {
                return Some(*v);
            }
        }
        None
    }

    fn prio(&self) -> Option<u32> {
        for a in self {
            if let Attribute::Priority(v) = a {
                return Some(*v);
            }
        }
        None
    }

    fn use_candidate(&self) -> bool {
        self.iter().any(|a| matches!(a, Attribute::UseCandidate))
    }

    fn message_integrity(&self) -> Option<&'a [u8]> {
        for a in self {
            if let Attribute::MessageIntegrity(v) = a {
                return Some(v);
            }
        }
        None
    }
}

use std::{io, str};

impl<'a> Attribute<'a> {
    fn padded_len(&self) -> usize {
        use Attribute::*;
        4 + match self {
            Username(v) => {
                let pad = 4 - (v.as_bytes().len() % 4) % 4;
                v.len() + pad
            }
            IceControlled(_) => 8,
            IceControlling(_) => 8,
            MessageIntegrityMark => 20,
            FingerprintMark => 4,
            Priority(_) => 4,
            XorMappedAddress(v) => {
                if v.is_ipv4() {
                    5
                } else {
                    17
                }
            }
            _ => panic!("No length for: {:?}", self),
        }
    }

    fn to_bytes(&self, vec: &mut dyn Write, trans_id: &[u8]) -> io::Result<()> {
        use Attribute::*;
        match self {
            Username(v) => {
                vec.write_all(&0x0006_u16.to_be_bytes())?;
                vec.write_all(&(v.as_bytes().len() as u16).to_be_bytes())?;
                vec.write_all(v.as_bytes())?;
                let pad = 4 - (v.as_bytes().len() % 4) % 4;
                for _ in 0..pad {
                    vec.write_all(&[0])?;
                }
            }
            IceControlled(v) => {
                vec.write_all(&0x8029_u16.to_be_bytes())?;
                vec.write_all(&8_u16.to_be_bytes())?;
                vec.write_all(&v.to_be_bytes())?;
            }
            IceControlling(v) => {
                vec.write_all(&0x802a_u16.to_be_bytes())?;
                vec.write_all(&8_u16.to_be_bytes())?;
                vec.write_all(&v.to_be_bytes())?;
            }
            MessageIntegrityMark => {
                vec.write_all(&0x0008_u16.to_be_bytes())?;
                vec.write_all(&20_u16.to_be_bytes())?;
                vec.write_all(&[0; 20])?; // filled in later
            }
            FingerprintMark => {
                vec.write_all(&0x8028_u16.to_be_bytes())?;
                vec.write_all(&4_u16.to_be_bytes())?;
                vec.write_all(&[0; 4])?; // filled in later
            }
            Priority(v) => {
                vec.write_all(&0x0024_u16.to_be_bytes())?;
                vec.write_all(&4_u16.to_be_bytes())?;
                vec.write_all(&v.to_be_bytes())?;
            }
            XorMappedAddress(v) => {
                let mut buf = [0_u8; 17];
                let len = encode_xor(*v, &mut buf, trans_id);
                vec.write_all(&buf[0..len])?;
            }
            _ => panic!("Can't write bytes for: {:?}", self),
        }

        Ok(())
    }

    fn parse(
        mut buf: &'a [u8],
        trans_id: &'a [u8],
        msg_integrity_off: &mut usize,
    ) -> Result<Vec<Attribute<'a>>, StunError> {
        let mut ret = vec![];
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
            // trace!(
            //     "STUN attribute typ 0x{:04x?} len {}: {:02x?}",
            //     typ,
            //     len,
            //     buf
            // );
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
                        ret.push(Attribute::MappedAddress);
                    }
                    0x0006 => {
                        ret.push(Attribute::Username(decode_str(typ, &buf[4..], len)?));
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
                        ret.push(Attribute::MessageIntegrity(&buf[4..24]));
                    }
                    0x0009 => {
                        if buf[4] != 0 || buf[5] != 0 || buf[6] & 0b1111_1000 != 0 {
                            return Err(StunError::Parse("Expected 0 at top of error code".into()));
                        }
                        let class = buf[6] as u16 * 100;
                        if class < 300 || class > 699 {
                            return Err(StunError::Parse(format!(
                                "Error class is not in range: {}",
                                class
                            )));
                        }
                        let code = class + (buf[7] % 100) as u16;
                        ret.push(Attribute::ErrorCode(
                            code,
                            decode_str(typ, &buf[8..], len - 4)?,
                        ));
                    }
                    0x000a => {
                        warn!("STUN got UnknownAttributes");
                        ret.push(Attribute::UnknownAttributes);
                    }
                    0x0014 => {
                        ret.push(Attribute::Realm(decode_str(typ, &buf[4..], len)?));
                    }
                    0x0015 => {
                        ret.push(Attribute::Nonce(decode_str(typ, &buf[4..], len)?));
                    }
                    0x0020 => {
                        ret.push(Attribute::XorMappedAddress(decode_xor(
                            &buf[4..],
                            trans_id,
                        )?));
                    }
                    0x0022 => {
                        ret.push(Attribute::Software(decode_str(typ, &buf[4..], len)?));
                    }
                    0x0024 => {
                        if len != 4 {
                            return Err(StunError::Parse("Priority that isnt 4 in length".into()));
                        }
                        let bytes = [buf[4], buf[5], buf[6], buf[7]];
                        ret.push(Attribute::Priority(u32::from_be_bytes(bytes)));
                    }
                    0x0025 => {
                        if len != 0 {
                            return Err(StunError::Parse(
                                "UseCandidate that isnt 0 in length".into(),
                            ));
                        }
                        ret.push(Attribute::UseCandidate);
                    }
                    0x8023 => {
                        warn!("STUN got AlternateServer");
                        ret.push(Attribute::AlternateServer);
                    }
                    0x8028 => {
                        let bytes = [buf[4], buf[5], buf[6], buf[7]];
                        ret.push(Attribute::Fingerprint(u32::from_be_bytes(bytes)));
                    }
                    0x8029 => {
                        if len != 8 {
                            return Err(StunError::Parse(
                                "IceControlled that isnt 8 in length".into(),
                            ));
                        }
                        let mut bytes = [0_u8; 8];
                        bytes.copy_from_slice(&buf[4..(4 + 8)]);
                        ret.push(Attribute::IceControlled(u64::from_be_bytes(bytes)));
                    }
                    0x802a => {
                        if len != 8 {
                            return Err(StunError::Parse(
                                "IceControlling that isnt 8 in length".into(),
                            ));
                        }
                        let mut bytes = [0_u8; 8];
                        bytes.copy_from_slice(&buf[4..(4 + 8)]);
                        ret.push(Attribute::IceControlling(u64::from_be_bytes(bytes)));
                    }
                    0xc057 => {
                        if len != 4 {
                            warn!("NetworkCost that isnt 4 in length");
                        } else {
                            let net_id = (buf[4] as u16) << 8 | buf[5] as u16;
                            let cost = (buf[6] as u16) << 8 | buf[7] as u16;
                            ret.push(Attribute::NetworkCost(net_id, cost));
                        }
                    }
                    _ => {
                        ret.push(Attribute::Unknown(typ));
                    }
                }
            }
            // attributes are on even 32 bit boundaries
            let pad = (4 - (len % 4)) % 4;
            let pad_len = len + pad;
            buf = &buf[(4 + pad_len)..];
            off += 4 + pad_len;
        }
        Ok(ret)
    }
}

fn decode_str(typ: u16, buf: &[u8], len: usize) -> Result<&str, StunError> {
    if len > 128 {
        return Err(StunError::Parse(format!(
            "0x{:04x?} too long str len: {}",
            typ, len
        )));
    }
    match str::from_utf8(&buf[0..len]).ok() {
        Some(v) => Ok(v),
        None => Err(StunError::Parse(format!("0x{:04x?} malformed utf-8", typ))),
    }
}

fn encode_xor(addr: SocketAddr, buf: &mut [u8; 17], trans_id: &[u8]) -> usize {
    let port = addr.port() ^ 0x2112;
    (&mut buf[2..4]).copy_from_slice(&port.to_be_bytes());
    buf[1] = if addr.is_ipv4() { 1 } else { 2 };
    let ip_buf = &mut buf[4..];
    match addr {
        SocketAddr::V4(v) => {
            let bytes = v.ip().octets();
            for i in 0..4 {
                ip_buf[i] = bytes[i] ^ MAGIC[i];
            }
            5
        }
        SocketAddr::V6(v) => {
            let bytes = v.ip().octets();
            for i in 0..4 {
                ip_buf[i] = bytes[i] ^ MAGIC[i];
            }
            for i in 4..16 {
                ip_buf[i] = bytes[i] ^ trans_id[i - 4];
            }
            17
        }
    }
}

fn decode_xor(buf: &[u8], trans_id: &[u8]) -> Result<SocketAddr, StunError> {
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
                bytes[i] = ip_buf[i] ^ trans_id[i - 4];
            }
            IpAddr::V6(bytes.into())
        }
        e => {
            return Err(StunError::Parse(format!("Invalid address family: {:?}", e)));
        }
    };

    Ok(SocketAddr::new(ip, port))
}

pub type HmacSha1 = Hmac<Sha1>;

pub fn hmac_sha1(secret: &[u8], payload: &[u8]) -> [u8; 20] {
    let mut hmac = HmacSha1::new_from_slice(secret).expect("Make HMAC-SHA1");
    hmac.update(payload);
    let comp = hmac.finalize().into_bytes();
    comp.into()
}
