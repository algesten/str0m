use crc::{Crc, CRC_32_ISCSI};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::chunk::{Chunk, Header, WriteTo};
use crate::{pad4, SctpAssociation, SctpError, MTU};

pub fn parse_chunks(buf: &mut [u8]) -> Result<Vec<Chunk>, SctpError> {
    let header = Header::try_from(&*buf)?;

    // zero the checksum to calculate a new crc
    buf[8..12].copy_from_slice(&0_u32.to_be_bytes());

    if header.checksum != sctp_crc(buf) {
        return Err(SctpError::BadChecksum);
    }

    let mut ret = vec![Chunk::Header(header)];

    let mut buf = &buf[12..];
    while !buf.is_empty() {
        let c = Chunk::try_from(buf)?;
        let len = c.parsed_len();
        ret.push(c);
        buf = &buf[pad4(len)..];
    }

    Ok(ret)
}

impl SctpAssociation {
    pub(crate) fn write_chunks(&mut self) -> Option<Vec<u8>> {
        if self.to_send.is_empty() {
            return None;
        }

        let Some(verification_tag) = self.association_tag_remote else {
            return None;
        };

        let mut vec = vec![0_u8; MTU];

        let header = Header {
            source_port: 5000,
            destination_port: 5000,
            verification_tag,
            checksum: 0,
        };

        let mut buf = &mut vec[..];
        header.write_to(buf);

        let mut len = header.len();
        buf = &mut buf[len..];
        while let Some(next) = self.to_send.front() {
            let c_len = pad4(next.len());

            if buf.len() < c_len {
                break;
            }

            // We're certain to write the chunk, pop it from the queue.
            let mut next = self.to_send.pop_front().unwrap();

            // Writes values for the chunk into the chunk header.
            next.update_chunk_header();

            next.write_to(buf);
            len += c_len;

            buf = &mut buf[c_len..];
        }

        vec.truncate(len);
        let checksum = sctp_crc(&vec[..]);

        (&mut vec[8..12]).copy_from_slice(&checksum.to_be_bytes());

        Some(vec)
    }
}

fn sctp_crc(buf: &[u8]) -> u32 {
    const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);
    let mut digest = CRC.digest();
    digest.update(&buf);
    // The CRC library calculates something that is reverse from what we expect when
    // writing to the wire i big endian.
    digest.finalize().swap_bytes()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StateCookie {
    pub salt: u32,
    pub checksum: [u8; 32],
}

impl StateCookie {
    pub fn new(secret: &[u8]) -> Self {
        let salt: u32 = rand::random();
        let mut cookie = StateCookie {
            salt,
            ..Default::default()
        };
        let bytes = cookie.to_bytes();
        let checksum = hmac_sha256(secret, &bytes);
        cookie.checksum = checksum;
        cookie
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0_u8; 36];
        buf[0..4].copy_from_slice(&self.salt.to_be_bytes());
        buf[4..].copy_from_slice(&self.checksum);
        buf
    }

    pub(crate) fn check_valid(&self, secret: &[u8]) -> bool {
        let mut c = *self;
        c.checksum.fill(0_u8);
        let bytes = c.to_bytes();
        let checksum = hmac_sha256(secret, &bytes);
        self.checksum == checksum
    }
}

impl TryFrom<&[u8]> for StateCookie {
    type Error = SctpError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 36 {
            return Err(SctpError::ShortPacket);
        }
        let mut cookie = StateCookie {
            salt: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            ..Default::default()
        };
        cookie.checksum.copy_from_slice(&buf[4..36]);
        Ok(cookie)
    }
}

pub fn hmac_sha256(secret: &[u8], payload: &[u8]) -> [u8; 32] {
    type HmacSha1 = Hmac<Sha256>;
    let mut hmac = HmacSha1::new_from_slice(secret).expect("Make HMAC-SHA1");
    hmac.update(payload);
    let comp = hmac.finalize().into_bytes();
    comp.into()
}
