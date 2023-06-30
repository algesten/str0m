use std::fmt;

use openssl::cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::dtls::KeyingMaterial;
use crate::io::Sha1;

use super::header::RtpHeader;

pub const SRTP_BLOCK_SIZE: usize = 16;
const SRTP_HMAC_LEN: usize = 10;
pub const SRTP_OVERHEAD: usize = 10;

// header = 4 bytes
// ssrc   = 4 bytes
// ssrtcp_index = 4 bytes
// hmac = 10 bytes
// TOTAL overhead for SRTCP = 22 bytes.
// However, each RTCP packet must be on a 4 byte boundary since length is
// given in number of 4 bytes - 1 (making 0 valid).

const SRTCP_INDEX_LEN: usize = 4;
pub const SRTCP_OVERHEAD: usize = 16;

#[derive(Debug)]
pub struct SrtpContext {
    /// Encryption/decryption derived from srtp_key for RTP.
    rtp: Derived,
    /// Encryption/decryption derived from srtp_key for RTCP.
    rtcp: Derived,
    /// Counter for outgoing SRTCP packets.
    srtcp_index: u32,
}

impl SrtpContext {
    pub fn new(srtp_key: SrtpKey) -> Self {
        let (rtp, rtcp) = Derived::from_key(&srtp_key);

        SrtpContext {
            rtp,
            rtcp,
            srtcp_index: 0,
        }
    }

    // SRTP layout
    // [header, [rtp, (padding + pad_count)], hmac]

    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
    //    |V=2|P|X|  CC   |M|     PT      |       sequence number         | |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
    //    |                           timestamp                           | |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
    //    |           synchronization source (SSRC) identifier            | |
    //    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
    //    |            contributing source (CSRC) identifiers             | |
    //    |                               ....                            | |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
    //    |                   RTP extension (OPTIONAL)                    | |
    //  +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
    //  | |                          payload  ...                         | |
    //  | |                               +-------------------------------+ |
    //  | |                               | RTP padding   | RTP pad count | |
    //  +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
    //  | ~                     SRTP MKI (OPTIONAL)                       ~ |
    //  | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
    //  | :                 authentication tag (RECOMMENDED)              : |
    //  | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
    //  |                                                                   |
    //  +- Encrypted Portion*                      Authenticated Portion ---+

    pub fn protect_rtp(
        &mut self,
        buf: &[u8],
        header: &RtpHeader,
        srtp_index: u64, // same as ext_seq
    ) -> Vec<u8> {
        let iv = self.rtp.salt.rtp_iv(*header.ssrc, srtp_index);

        let hlen = header.header_len;
        let input = &buf[hlen..];
        assert!(
            input.len() % SRTP_BLOCK_SIZE == 0,
            "RTP body should be padded to 16 byte block size, {header:?} with body length {} was not", input.len()
        );

        let mut output = vec![0_u8; buf.len() + SRTP_HMAC_LEN];
        self.rtp
            .enc
            .encrypt(&iv, input, &mut output[hlen..])
            .expect("rtp encrypt");

        output[..hlen].copy_from_slice(&buf[..hlen]);

        let hmac_start = buf.len();
        self.rtp.hmac.rtp_hmac(&mut output, srtp_index, hmac_start);

        output
    }

    pub fn unprotect_rtp(
        &mut self,
        buf: &[u8],
        header: &RtpHeader,
        srtp_index: u64, // same as ext_seq
    ) -> Option<Vec<u8>> {
        if buf.len() < SRTP_HMAC_LEN {
            return None;
        }

        let hmac_start = buf.len() - SRTP_HMAC_LEN;

        if !self
            .rtp
            .hmac
            .rtp_verify(&buf[..hmac_start], srtp_index, &buf[hmac_start..])
        {
            trace!("unprotect_rtp hmac verify fail");
            return None;
        }

        let iv = self.rtp.salt.rtp_iv(*header.ssrc, srtp_index);

        let input = &buf[header.header_len..hmac_start];
        // Allocate enough to also hold a header, since this is used in rtp-mode.
        let mut output = Vec::with_capacity(buf.len());
        output.resize(input.len(), 0);

        // TODO: This instantiates a Crypter for every packet. That's kinda wasteful
        // when it's perfectly possible to reuse the underlying OpenSSL structs for
        // over and over using a reset.
        self.rtp
            .dec
            .decrypt(&iv, input, &mut output)
            .expect("rtp decrypt");

        if truncate_off_srtp_padding(header.has_padding, &mut output).is_err() {
            trace!("unpadding of unprotected payload failed");
            return None;
        }

        Some(output)
    }

    pub fn protect_rtcp(&mut self, buf: &[u8]) -> Vec<u8> {
        // https://tools.ietf.org/html/rfc3711#page-15
        // The SRTCP index MUST be set to zero before the first SRTCP
        // packet is sent, and MUST be incremented by one,
        // modulo 2^31, after each SRTCP packet is sent.
        self.srtcp_index = (self.srtcp_index + 1) % 2_u32.pow(31);

        let srtcp_index = self.srtcp_index;
        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        if ssrc == 0 {
            warn!("SSRC 0 does not make a good SRTCP IV");
        }

        let iv = self.rtcp.salt.rtp_iv(ssrc, srtcp_index as u64);

        let mut output = vec![0_u8; buf.len() + SRTCP_INDEX_LEN + SRTP_HMAC_LEN];
        output[0..8].copy_from_slice(&buf[0..8]);
        let input = &buf[8..];
        let encout = &mut output[8..(8 + input.len())];

        self.rtcp
            .enc
            .encrypt(&iv, input, encout)
            .expect("rtcp encrypt");

        // e is always encrypted, rest is 31 byte index.
        let e_and_si = 0x8000_0000 | srtcp_index;
        let to = &mut output[buf.len()..];
        to[0..4].copy_from_slice(&e_and_si.to_be_bytes());

        let hmac_index = output.len() - SRTP_HMAC_LEN;
        self.rtcp.hmac.rtcp_hmac(&mut output, hmac_index);

        output
    }

    // SRTCP layout
    // ["header", ssrc, payload, ["header", ssrc, payload], ...], ssrtcp_index, hmac]
    //
    // |----------------------------------------------------------------------|
    //                          authenticated (hmac)
    //
    //                  |--------------------------------------|
    //                              encrypted (aes)

    pub fn unprotect_rtcp(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < SRTP_HMAC_LEN + SRTCP_INDEX_LEN {
            return None;
        }

        let hmac_start = buf.len() - SRTP_HMAC_LEN;

        if !self
            .rtcp
            .hmac
            .rtcp_verify(&buf[..hmac_start], &buf[hmac_start..])
        {
            trace!("unprotect_rtcp hmac verify fail");
            return None;
        }

        let idx_start = hmac_start - SRTCP_INDEX_LEN;

        let srtcp_index_be = [
            buf[idx_start],
            buf[idx_start + 1],
            buf[idx_start + 2],
            buf[idx_start + 3],
        ];

        // E-flag and SRTCP index.
        let e_and_si = u32::from_be_bytes(srtcp_index_be);

        let is_encrypted = e_and_si & 0x8000_0000 > 0;

        if !is_encrypted {
            // Non-encrypted we can just return
            return Some(buf[0..idx_start].to_vec());
        }

        // The SRTCP index is a 31-bit counter for the SRTCP packet.
        let srtcp_index = e_and_si & 0x7fff_ffff;
        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        let iv = self.rtcp.salt.rtp_iv(ssrc, srtcp_index as u64);

        // The Encrypted Portion of an SRTCP packet consists of the encryption
        // of the RTCP payload of the equivalent compound RTCP packet, from the
        // first RTCP packet, i.e., from the ninth (9) octet to the end of the
        // compound packet.
        let input = &buf[8..idx_start];
        let mut output = vec![0_u8; input.len() + 8];
        output[0..8].copy_from_slice(&buf[0..8]);

        self.rtcp
            .dec
            .decrypt(&iv, input, &mut output[8..])
            .expect("rtcp decrypt");

        Some(output)
    }
}

fn truncate_off_srtp_padding(has_padding: bool, payload: &mut Vec<u8>) -> Result<(), ()> {
    if has_padding {
        let pad_len = payload[payload.len() - 1] as usize;
        let Some(unpadded_len) = payload.len().checked_sub(pad_len) else {
            return Err(())
        };
        payload.truncate(unpadded_len);
    }
    Ok(())
}

/// SrtpKeys created from DTLS SrtpKeyMaterial.
#[derive(Debug)]
pub struct SrtpKey {
    master: [u8; 16],
    salt: [u8; 14],
}

impl SrtpKey {
    pub fn new(mat: &KeyingMaterial, left: bool) -> Self {
        // layout in SrtpKeyMaterial is [key_input, key_output, salt_input, salt_output]

        const ML: usize = 16; // master len
        const SL: usize = 14; // salt len

        // offset 0, offset 1
        let (o0, o1) = if left { (0, 0) } else { (ML, SL) };

        let mut master = [0; ML];
        let mut salt = [0; SL];

        master[0..ML].copy_from_slice(&mat[o0..(o0 + ML)]);
        salt[0..SL].copy_from_slice(&mat[(ML + ML + o1)..(ML + ML + o1 + SL)]);

        SrtpKey { master, salt }
    }

    fn derive(&self, label: u8, out: &mut [u8]) {
        let mut i = 0; // index in out

        // input layout: [salt[14] || label, round[2]] (|| is xor 7th byte)
        let mut input = [0; 16];

        input[0..14].copy_from_slice(&self.salt[..]);
        input[7] ^= label;

        let mut buf = [0; 16 + 16]; // output from each AES
        let mut round: u16 = 0; // counter for each AES round

        // loop each AES round
        loop {
            if i == out.len() {
                break;
            }

            // splice in round at bottom of input
            input[14..].copy_from_slice(&round.to_be_bytes()[..]);

            // default key derivation function, which uses AES-128 in Counter Mode
            let mut aes = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &self.master, None)
                .expect("AES deriver");

            // Run AES
            let count = aes.update(&input[..], &mut buf[..]).expect("AES update");
            let rest = aes.finalize(&mut buf[count..]).expect("AES finalize");
            assert_eq!(count + rest, 16 + 16); // input len + block size

            // Copy to output. Even if we get 32 bytes of output with AES 128 ECB, we
            // only use the first 16. That matches the tests in the RFC.
            for j in buf.iter().take(16) {
                if i == out.len() {
                    break;
                }
                out[i] = *j;
                i += 1;
            }

            round += 1;
        }
    }
}

/// Encryption/decryption derived from the SrtpKey.
struct Derived {
    hmac: Sha1,
    salt: RtpSalt,
    enc: Encrypter,
    dec: Decrypter,
}

type AesKey = [u8; 16];
type RtpSalt = [u8; 14];
type RtpIv = [u8; 16];

impl Derived {
    fn from_key(srtp_key: &SrtpKey) -> (Self, Self) {
        // RTP AES Counter

        const LABEL_RTP_AES: u8 = 0;
        let mut rtp_aes = [0; 16];
        srtp_key.derive(LABEL_RTP_AES, &mut rtp_aes[..]);

        // RTP SHA1 HMAC

        let rtp_hmac = {
            const LABEL_RTP_HMAC: u8 = 1;
            let mut hmac = [0; 20];
            srtp_key.derive(LABEL_RTP_HMAC, &mut hmac[..]);
            (&hmac[..]).into()
        };

        // RTP IV SALT

        const LABEL_RTP_SALT: u8 = 2;
        let mut rtp_salt = [0; 14];
        srtp_key.derive(LABEL_RTP_SALT, &mut rtp_salt[..]);

        // RTCP AES Counter

        const LABEL_RTCP_AES: u8 = 3;
        let mut rtcp_aes = [0; 16];
        srtp_key.derive(LABEL_RTCP_AES, &mut rtcp_aes[..]);

        // RTCP SHA1 HMAC

        let rtcp_hmac = {
            const LABEL_RTCP_HMAC: u8 = 4;
            let mut hmac = [0; 20];
            srtp_key.derive(LABEL_RTCP_HMAC, &mut hmac[..]);
            (&hmac[..]).into()
        };

        // RTCP IV SALT

        const LABEL_RTCP_SALT: u8 = 5;
        let mut rtcp_salt = [0; 14];
        srtp_key.derive(LABEL_RTCP_SALT, &mut rtcp_salt[..]);

        let rtp = Derived {
            hmac: rtp_hmac,
            salt: rtp_salt,
            enc: Encrypter::new(rtp_aes),
            dec: Decrypter::new(rtp_aes),
        };

        let rtcp = Derived {
            hmac: rtcp_hmac,
            salt: rtcp_salt,
            enc: Encrypter::new(rtcp_aes),
            dec: Decrypter::new(rtcp_aes),
        };

        (rtp, rtcp)
    }
}

struct Encrypter {
    ctx: CipherCtx,
}

impl Encrypter {
    fn new(key: AesKey) -> Self {
        let t = cipher::Cipher::aes_128_ctr();
        let mut ctx = CipherCtx::new().expect("a reusable cipher context");
        ctx.encrypt_init(Some(t), Some(&key[..]), None)
            .expect("enc init");
        Encrypter { ctx }
    }

    fn encrypt(&mut self, iv: &RtpIv, input: &[u8], output: &mut [u8]) -> Result<(), ErrorStack> {
        self.ctx.encrypt_init(None, None, Some(iv))?;
        let count = self.ctx.cipher_update(input, Some(output))?;
        self.ctx.cipher_final(&mut output[count..])?;
        Ok(())
    }
}

struct Decrypter {
    ctx: CipherCtx,
}

impl Decrypter {
    fn new(key: AesKey) -> Self {
        let t = cipher::Cipher::aes_128_ctr();
        let mut ctx = CipherCtx::new().expect("a reusable cipher context");
        ctx.decrypt_init(Some(t), Some(&key[..]), None)
            .expect("enc init");
        Decrypter { ctx }
    }

    fn decrypt(&mut self, iv: &RtpIv, input: &[u8], output: &mut [u8]) -> Result<(), ErrorStack> {
        self.ctx.decrypt_init(None, None, Some(iv))?;
        let count = self.ctx.cipher_update(input, Some(output))?;
        self.ctx.cipher_final(&mut output[count..])?;
        Ok(())
    }
}

trait RtpHmac {
    fn rtp_hmac(&self, buf: &mut [u8], srtp_index: u64, hmac_start: usize);
    fn rtp_verify(&self, buf: &[u8], srtp_index: u64, cmp: &[u8]) -> bool;
    fn rtcp_hmac(&self, buf: &mut [u8], hmac_index: usize);
    fn rtcp_verify(&self, buf: &[u8], cmp: &[u8]) -> bool;
}

impl RtpHmac for Sha1 {
    fn rtp_hmac(&self, buf: &mut [u8], srtp_index: u64, hmac_start: usize) {
        let sha1 = self.clone();

        let roc = (srtp_index >> 16) as u32;

        let tag = sha1.hmac(&[&buf[..hmac_start], &roc.to_be_bytes()]);

        buf[hmac_start..(hmac_start + SRTP_HMAC_LEN)].copy_from_slice(&tag[0..SRTP_HMAC_LEN]);
    }

    fn rtp_verify(&self, buf: &[u8], srtp_index: u64, cmp: &[u8]) -> bool {
        let sha1 = self.clone();

        let roc = (srtp_index >> 16) as u32;

        let tag = sha1.hmac(&[buf, &roc.to_be_bytes()]);

        &tag[0..SRTP_HMAC_LEN] == cmp
    }

    fn rtcp_hmac(&self, buf: &mut [u8], hmac_index: usize) {
        let sha1 = self.clone();

        let tag = sha1.hmac(&[&buf[0..hmac_index]]);

        buf[hmac_index..(hmac_index + SRTP_HMAC_LEN)].copy_from_slice(&tag[0..SRTP_HMAC_LEN]);
    }

    fn rtcp_verify(&self, buf: &[u8], cmp: &[u8]) -> bool {
        let sha1 = self.clone();

        let tag = sha1.hmac(&[buf]);

        &tag[0..SRTP_HMAC_LEN] == cmp
    }
}

trait ToRtpIv {
    fn rtp_iv(&self, ssrc: u32, srtp_index: u64) -> RtpIv;
}

impl ToRtpIv for RtpSalt {
    fn rtp_iv(&self, ssrc: u32, srtp_index: u64) -> RtpIv {
        let mut iv = [0; 16];

        let ssrc_be = ssrc.to_be_bytes();
        let srtp_be = srtp_index.to_be_bytes();

        iv[4..8].copy_from_slice(&ssrc_be);

        for i in 0..8 {
            iv[i + 6] ^= srtp_be[i];
        }
        for i in 0..14 {
            iv[i] ^= self[i];
        }

        iv
    }
}

impl fmt::Debug for Derived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Derived")
    }
}

impl fmt::Debug for Encrypter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encrypter").finish()
    }
}

impl fmt::Debug for Decrypter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decrypter").finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn derive_key() {
        // https://tools.ietf.org/html/rfc3711#appendix-B.3
        //
        // Key Derivation Test Vectors.

        let master = [
            0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, //
            0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39,
        ];

        let salt = [
            0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, //
            0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
        ];

        let sk = SrtpKey { master, salt };

        // aes crypto key
        let mut out = [0_u8; 16];
        sk.derive(0, &mut out[..]);

        assert_eq!(
            out,
            [
                0xC6, 0x1E, 0x7A, 0x93, 0x74, 0x4F, 0x39, 0xEE, //
                0x10, 0x73, 0x4A, 0xFE, 0x3F, 0xF7, 0xA0, 0x87
            ]
        );

        // hmac
        let mut out = [0_u8; 20];
        sk.derive(1, &mut out[..]);

        assert_eq!(
            out,
            [
                0xCE, 0xBE, 0x32, 0x1F, 0x6F, 0xF7, 0x71, 0x6B, //
                0x6F, 0xD4, 0xAB, 0x49, 0xAF, 0x25, 0x6A, 0x15, //
                0x6D, 0x38, 0xBA, 0xA4
            ]
        );

        // salt
        let mut out = [0_u8; 14];
        sk.derive(2, &mut out[..]);

        assert_eq!(
            out,
            [
                0x30, 0xCB, 0xBC, 0x08, 0x86, 0x3D, 0x8C, //
                0x85, 0xD4, 0x9D, 0xB3, 0x4A, 0x9A, 0xE1
            ]
        );
    }

    const MAT: [u8; 60] = [
        0x2C, 0xB0, 0x23, 0x46, 0xB4, 0x22, 0x76, 0xA6, 0x72, 0xCF, 0xD1, 0x43, 0xAE, 0xC2, 0xD5,
        0xEE, 0xDD, 0xDE, 0x55, 0xF0, 0xAD, 0x7B, 0xCA, 0xC2, 0x26, 0x66, 0xF1, 0xC6, 0x38, 0x61,
        0x73, 0xED, 0x6E, 0xB2, 0x5C, 0xB7, 0xD2, 0x6A, 0x61, 0xA1, 0xEE, 0x2C, 0x21, 0x0A, 0xDA,
        0xE7, 0x60, 0xAA, 0xA2, 0xFD, 0x67, 0xB6, 0x72, 0xC4, 0x1A, 0xED, 0x10, 0x5F, 0x9D, 0x36,
    ];

    const SRTCP: &[u8] = &[
        // header
        0x80, 0xC8, 0x00, 0x06, //
        // ssrc
        0x3C, 0xD7, 0xCC, 0x13, //
        // encrypted payload
        0xB7, 0xC8, 0x31, 0xDC, 0xB7, 0x76, 0xCD, 0x8D, 0xC2, 0x6F, 0xDA, 0x1D, 0x9B, 0xFC, 0x8E,
        0xE6, 0x58, 0x9A, 0x1A, 0x8A, 0x49, 0x28, 0x9C, 0xAE, 0xB2, 0x64, 0x20, 0x0C, 0x37, 0xD2,
        0xD0, 0xA4, 0xAF, 0xAC, 0x63, 0x85, 0xFF, 0xC6, 0x0D, 0xEC, 0x7D, 0x06, 0xD4, 0x87, 0x3D,
        0xD3, 0xA8, 0xCC, //
        // E flag and srtcp index (1)
        0x80, 0x00, 0x00, 0x01, //
        // hmac
        0xB7, 0xBB, 0x52, 0x65, 0x21, 0xD1, 0xE7, 0x3C, 0x0F, 0xC0,
    ];

    // #[test]
    // fn unprotect_rtcp() {
    //     let key_mat = KeyingMaterial::new(MAT);

    //     let key_rx = SrtpKey::new(&key_mat, true);

    //     let mut ctx_rx = SrtpContext::new(key_rx);

    //     let decrypted = ctx_rx.unprotect_rtcp(SRTCP);

    //     println!("{:02x?}", decrypted);
    // }

    #[test]
    fn protect_rtcp() {
        let key_mat = KeyingMaterial::new(MAT);
        let key_rx = SrtpKey::new(&key_mat, true);
        let mut ctx_rx = SrtpContext::new(key_rx);

        let decrypted = ctx_rx.unprotect_rtcp(SRTCP).unwrap();

        // check srtcp_index will be 1
        assert_eq!(ctx_rx.srtcp_index, 0);
        // check srtcp_index in incoming was indeed 1
        let srtcp_index = SRTCP.len() - SRTP_HMAC_LEN - SRTCP_INDEX_LEN;
        let e_and_i = &SRTCP[srtcp_index..(srtcp_index + 4)];
        assert_eq!(e_and_i, &0x8000_0001_u32.to_be_bytes());

        println!("{}", decrypted.len());
        println!("{decrypted:02x?}");

        // Take us back to where we started.
        let encrypted = ctx_rx.protect_rtcp(&decrypted);
        assert_eq!(encrypted, SRTCP);
    }

    #[test]
    fn truncate_off_srtp_padding() {
        let truncate = |has_padding, mut payload| -> Result<Vec<u8>, ()> {
            super::truncate_off_srtp_padding(has_padding, &mut payload)?;
            Ok(payload)
        };

        assert_eq!(Ok(vec![1, 2, 3, 4, 0]), truncate(true, vec![1, 2, 3, 4, 0]));
        assert_eq!(Ok(vec![1, 2, 3, 4]), truncate(true, vec![1, 2, 3, 4, 1]));
        assert_eq!(Ok(vec![1, 2, 3]), truncate(true, vec![1, 2, 3, 4, 2]));
        assert_eq!(Ok(vec![1, 2]), truncate(true, vec![1, 2, 3, 4, 3]));
        assert_eq!(Ok(vec![1]), truncate(true, vec![1, 2, 3, 4, 4]));
        assert_eq!(Ok(vec![]), truncate(true, vec![1, 2, 3, 4, 5]));
        assert_eq!(Err(()), truncate(true, vec![1, 2, 3, 4, 6]));
        assert_eq!(Err(()), truncate(true, vec![1, 2, 3, 4, 255]));
        assert_eq!(Ok(vec![0]), truncate(true, vec![0]));
        assert_eq!(Ok(vec![]), truncate(true, vec![1]));
        assert_eq!(Ok(vec![]), truncate(false, vec![]));
        assert_eq!(Ok(vec![1]), truncate(false, vec![1]));
        assert_eq!(Ok(vec![1, 2, 3, 4]), truncate(false, vec![1, 2, 3, 4]));
    }
}
