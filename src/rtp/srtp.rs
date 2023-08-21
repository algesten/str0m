use std::fmt;

use openssl::symm::{Cipher, Crypter, Mode};

use crate::dtls::KeyingMaterial;
use crate::io::Sha1;

use super::header::RtpHeader;

// Common among various profiles(defined in RFC3711 Section 4.3)
const LABEL_RTP_AES: u8 = 0;
const LABEL_RTP_AUTHENTICATION_KEY: u8 = 1;
const LABEL_RTP_SALT: u8 = 2;

const LABEL_RTCP_AES: u8 = 3;
const LABEL_RTCP_AUTHENTICATION_KEY: u8 = 4;
const LABEL_RTCP_SALT: u8 = 5;

// header = 4 bytes
// ssrc   = 4 bytes
// ssrtcp_index = 4 bytes
// tag = <T> bytes
// TOTAL overhead for SRTCP = 12 + T bytes.
// However, each RTCP packet must be on a 4 byte boundary since length is
// given in number of 4 bytes - 1 (making 0 valid).

pub const SRTP_BLOCK_SIZE: usize = 16;
const SRTCP_INDEX_LEN: usize = 4;
const MAX_TAG_LEN: usize = aead_aes_128_gcm::TAG_LEN;
pub const SRTCP_OVERHEAD: usize = MAX_TAG_LEN + SRTCP_INDEX_LEN;
pub const SRTP_OVERHEAD: usize = MAX_TAG_LEN;

#[derive(Debug)]
pub enum SrtpProfile {
    Aes128CmSha1_80,
    AeadAes128Gcm,
}

impl SrtpProfile {
    // All the profiles we support, ordered from most preferred to least.
    // TODO: Enable SrtpProfile::Aes128CmSha1_80
    pub(crate) const ALL: &[SrtpProfile] = &[SrtpProfile::Aes128CmSha1_80];

    /// The length of keying material to extract from the DTLS session in bytes.
    pub(crate) fn keying_material_len(&self) -> usize {
        match self {
            SrtpProfile::Aes128CmSha1_80 => aes_128_cm_sha1_80::KEYING_MATERIAL_LEN,
            SrtpProfile::AeadAes128Gcm => aead_aes_128_gcm::KEYING_MATERIAL_LEN,
        }
    }

    /// Create an SRTP context for the relevant profile using the provided keying material.
    pub(crate) fn create_context(&self, mat: &KeyingMaterial, left: bool) -> SrtpContext {
        match self {
            SrtpProfile::Aes128CmSha1_80 => {
                use aes_128_cm_sha1_80::{MASTER_KEY_LEN, MASTER_SALT_LEN};

                let key = SrtpKey::<MASTER_KEY_LEN, MASTER_SALT_LEN>::new(mat, left);

                let (rtp, rtcp) = Derived::aes_128_cm_sha1_80(&key);

                SrtpContext {
                    rtp,
                    rtcp,
                    srtcp_index: 0,
                }
            }
            SrtpProfile::AeadAes128Gcm => {
                use aead_aes_128_gcm::{MASTER_KEY_LEN, MASTER_SALT_LEN};

                let key = SrtpKey::<MASTER_KEY_LEN, MASTER_SALT_LEN>::new(mat, left);

                let (rtp, rtcp) = Derived::aead_aes_128_gcm(&key);

                SrtpContext {
                    rtp,
                    rtcp,
                    srtcp_index: 0,
                }
            }
        }
    }

    /// What this profile is called in OpenSSL parlance.
    pub(crate) fn openssl_name(&self) -> &'static str {
        match self {
            SrtpProfile::Aes128CmSha1_80 => "SRTP_AES128_CM_SHA1_80",
            SrtpProfile::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
        }
    }
}

impl fmt::Display for SrtpProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrtpProfile::Aes128CmSha1_80 => write!(f, "SRTP_AES128_CM_SHA1_80"),
            SrtpProfile::AeadAes128Gcm => write!(f, "SRTP_AEAD_AES_128_GCM"),
        }
    }
}

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
    pub fn protect_rtp(
        &mut self,
        buf: &[u8],
        header: &RtpHeader,
        srtp_index: u64, // same as ext_seq
    ) -> Vec<u8> {
        let hlen = header.header_len;
        let input = &buf[hlen..];

        assert!(
            input.len() % SRTP_BLOCK_SIZE == 0,
            "RTP body should be padded to 16 byte block size, {header:?} with body length {} was not", input.len()
        );

        match &mut self.rtp {
            Derived::Aes128CmSha1_80 {
                hmac, salt, enc, ..
            } => {
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

                use aes_128_cm_sha1_80::{RtpHmac, ToRtpIv, HMAC_TAG_LEN};

                let iv = salt.rtp_iv(*header.ssrc, srtp_index);

                let mut output = vec![0_u8; buf.len() + HMAC_TAG_LEN];
                enc.encrypt(&iv, input, &mut output[hlen..])
                    .expect("rtp encrypt");

                output[..hlen].copy_from_slice(&buf[..hlen]);

                let hmac_start = buf.len();
                hmac.rtp_hmac(&mut output, srtp_index, hmac_start);

                output
            }
            Derived::AeadAes128Gcm { salt, enc, .. } => {
                use aead_aes_128_gcm::{ToRtpIv, TAG_LEN};
                let roc = (srtp_index >> 16) as u32;

                let iv = salt.rtp_iv(*header.ssrc, roc, header.sequence_number);
                let aad = &buf[..hlen];

                let mut output = vec![0_u8; buf.len() + TAG_LEN];
                enc.encrypt(&iv, aad, input, &mut output[hlen..])
                    .expect("rtp encrypt");

                output[..hlen].copy_from_slice(aad);

                output
            }
        }
    }

    pub fn unprotect_rtp(
        &mut self,
        buf: &[u8],
        header: &RtpHeader,
        srtp_index: u64, // same as ext_seq
    ) -> Option<Vec<u8>> {
        match &mut self.rtp {
            Derived::Aes128CmSha1_80 {
                hmac, salt, dec, ..
            } => {
                use aes_128_cm_sha1_80::{RtpHmac, ToRtpIv, HMAC_TAG_LEN};

                if buf.len() < HMAC_TAG_LEN {
                    return None;
                }

                let hmac_start = buf.len() - HMAC_TAG_LEN;

                if !hmac.rtp_verify(&buf[..hmac_start], srtp_index, &buf[hmac_start..]) {
                    trace!("unprotect_rtp hmac verify fail");
                    return None;
                }

                let iv = salt.rtp_iv(*header.ssrc, srtp_index);

                let input = &buf[header.header_len..hmac_start];
                // Allocate enough to also hold a header, since this is used in rtp-mode.
                let mut output = Vec::with_capacity(buf.len());
                output.resize(input.len(), 0);

                // TODO: This instantiates a Crypter for every packet. That's kinda wasteful
                // when it's perfectly possible to reuse the underlying OpenSSL structs for
                // over and over using a reset.
                dec.decrypt(&iv, input, &mut output).expect("rtp decrypt");

                Some(output)
            }
            Derived::AeadAes128Gcm { salt, dec, .. } => {
                use aead_aes_128_gcm::{ToRtpIv, TAG_LEN};

                if buf.len() < TAG_LEN {
                    return None;
                }

                let roc: u32 = (srtp_index >> 16) as u32;
                let seq = header.sequence_number;

                let iv = salt.rtp_iv(*header.ssrc, roc, seq);

                let (aad, input) = buf.split_at(header.header_len);
                // TODO: This doesn't seem aligned with the comment here:
                // https://github.com/algesten/str0m/blob/2c59d484ea2748dc4e8535d26188fab6acf4ed39/src/streams/mod.rs#L58-L59
                // Allocate enough to also hold a header, since this is used in rtp-mode.
                let mut output = vec![0; buf.len()];

                // TODO: This expect is problematic
                let count = dec
                    .decrypt(&iv, aad, input, &mut output)
                    .expect("rtp decrypt");

                output.truncate(count);

                Some(output)
            }
        }
    }

    pub fn protect_rtcp(&mut self, buf: &[u8]) -> Vec<u8> {
        // https://tools.ietf.org/html/rfc3711#page-15
        // The SRTCP index MUST be set to zero before the first SRTCP
        // packet is sent, and MUST be incremented by one,
        // modulo 2^31, after each SRTCP packet is sent.
        self.srtcp_index = (self.srtcp_index + 1) % 2_u32.pow(31);

        let srtcp_index = self.srtcp_index;
        // e is always encrypted, rest is 31 byte index.
        let e_and_si = 0x8000_0000 | srtcp_index;
        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        if ssrc == 0 {
            warn!("SSRC 0 does not make a good SRTCP IV");
        }

        match &mut self.rtcp {
            Derived::Aes128CmSha1_80 {
                hmac, salt, enc, ..
            } => {
                use aes_128_cm_sha1_80::{RtpHmac, ToRtpIv, HMAC_TAG_LEN};

                let iv = salt.rtp_iv(ssrc, srtcp_index as u64);

                let mut output = vec![0_u8; buf.len() + SRTCP_INDEX_LEN + HMAC_TAG_LEN];
                output[0..8].copy_from_slice(&buf[0..8]);
                let input = &buf[8..];
                let encout = &mut output[8..(8 + input.len())];

                enc.encrypt(&iv, input, encout).expect("rtcp encrypt");

                let to = &mut output[buf.len()..];
                to[0..4].copy_from_slice(&e_and_si.to_be_bytes());

                let hmac_index = output.len() - HMAC_TAG_LEN;
                hmac.rtcp_hmac(&mut output, hmac_index);

                output
            }
            Derived::AeadAes128Gcm { salt, enc, .. } => {
                use aead_aes_128_gcm::{ToRtpIv, RTCP_AAD_LEN, TAG_LEN};
                let iv = salt.rtcp_iv(ssrc, srtcp_index);

                let mut aad = [0; RTCP_AAD_LEN];
                aad[..8].copy_from_slice(&buf[..8]);
                aad[8..12].copy_from_slice(&e_and_si.to_be_bytes());

                let mut output = vec![0_u8; buf.len() + SRTCP_INDEX_LEN + TAG_LEN];
                output[0..8].copy_from_slice(&buf[0..8]);
                let input = &buf[8..];

                let enc_start = 8;
                let enc_end = input.len() + 8 + TAG_LEN;
                let encout = &mut output[enc_start..enc_end];

                enc.encrypt(&iv, &aad, input, encout).expect("rtcp encrypt");

                let to = &mut output[enc_end..];
                to[0..4].copy_from_slice(&e_and_si.to_be_bytes());

                output
            }
        }
    }

    pub fn unprotect_rtcp(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        match &mut self.rtcp {
            Derived::Aes128CmSha1_80 {
                hmac, salt, dec, ..
            } => {
                // SRTCP layout
                // ["header", ssrc, payload, ["header", ssrc, payload], ...], ssrtcp_index, hmac]
                //
                // |----------------------------------------------------------------------|
                //                          authenticated (hmac)
                //
                //                  |--------------------------------------|
                //                              encrypted (aes)
                use aes_128_cm_sha1_80::{RtpHmac, ToRtpIv, HMAC_TAG_LEN};

                if buf.len() < HMAC_TAG_LEN + SRTCP_INDEX_LEN {
                    return None;
                }

                let hmac_start = buf.len() - HMAC_TAG_LEN;

                if !hmac.rtcp_verify(&buf[..hmac_start], &buf[hmac_start..]) {
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

                let iv = salt.rtp_iv(ssrc, srtcp_index as u64);

                // The Encrypted Portion of an SRTCP packet consists of the encryption
                // of the RTCP payload of the equivalent compound RTCP packet, from the
                // first RTCP packet, i.e., from the ninth (9) octet to the end of the
                // compound packet.
                let input = &buf[8..idx_start];
                let mut output = vec![0_u8; input.len() + 8];
                output[0..8].copy_from_slice(&buf[0..8]);

                dec.decrypt(&iv, input, &mut output[8..])
                    .expect("rtcp decrypt");

                Some(output)
            }
            Derived::AeadAes128Gcm { salt, dec, .. } => {
                use aead_aes_128_gcm::{ToRtpIv, RTCP_AAD_LEN, TAG_LEN};

                if buf.len() < SRTCP_INDEX_LEN + TAG_LEN {
                    // Too short
                    return None;
                }

                let idx_start = buf.len() - SRTCP_INDEX_LEN;

                // Assume no MKI
                let e_and_si = u32::from_be_bytes(
                    buf[idx_start..buf.len()]
                        .try_into()
                        // This is ok because SRTCP_INDEX_LEN is 4 bytes and the buffer is at least
                        // that long.
                        .expect("SRTCP_INDEX_LEN to be 4"),
                );
                let is_encrypted = e_and_si & 0x8000_0000 > 0;
                if !is_encrypted {
                    todo!("Handle unecrypted RTCP");
                }

                // The SRTCP index is a 31-bit counter for the SRTCP packet.
                let srtcp_index = e_and_si & 0x7fff_ffff;
                let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

                let iv = salt.rtcp_iv(ssrc, srtcp_index);
                let mut aad = [0; RTCP_AAD_LEN];
                aad[0..8].copy_from_slice(&buf[0..8]);
                aad[8..12].copy_from_slice(&e_and_si.to_be_bytes());

                // The Encrypted Portion of an SRTCP packet consists of the encryption
                // of the RTCP payload of the equivalent compound RTCP packet, from the
                // first RTCP packet, i.e., from the ninth (9) octet to the end of the
                // compound packet.
                let input = &buf[8..idx_start];
                let mut output = vec![0_u8; input.len() + 8];
                output[0..8].copy_from_slice(&buf[0..8]);

                dec.decrypt(&iv, &aad, input, &mut output[8..])
                    .expect("rtcp decrypt");

                Some(output)
            }
        }
    }
}

/// SrtpKeys created from DTLS SrtpKeyMaterial.
#[derive(Debug)]
struct SrtpKey<const ML: usize, const SL: usize> {
    master: [u8; ML],
    salt: [u8; SL],
}

impl<const ML: usize, const SL: usize> SrtpKey<ML, SL> {
    pub fn new(mat: &KeyingMaterial, left: bool) -> Self {
        // layout in SrtpKeyMaterial is [key_input, key_output, salt_input, salt_output]

        // Invariant
        assert!(
            mat.len() == ML * 2 + SL * 2,
            "The KeyingMaterial provided to SrtpKey::new must be ML * 2 + SL * 2 in length"
        );

        // offset 0, offset 1
        let (o0, o1) = if left { (0, 0) } else { (ML, SL) };

        let mut master = [0; ML];
        let mut salt = [0; SL];

        master[0..ML].copy_from_slice(&mat[o0..(o0 + ML)]);
        salt[0..SL].copy_from_slice(&mat[(ML + ML + o1)..(ML + ML + o1 + SL)]);

        SrtpKey { master, salt }
    }

    fn derive(&self, label: u8, out: &mut [u8]) {
        // AEC-CM (128 bits) defined in RFC3711
        assert!(ML == 16, "Only valid for 128 bit master keys");
        assert!(SL <= 14, "Only valid for 128 bit master keys");
        let mut i = 0; // index in out

        // input layout: [salt[SL] || label, round[2]] (|| is xor 7th byte)
        let mut input = [0; ML];

        input[0..SL].copy_from_slice(&self.salt[..]);
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
enum Derived {
    Aes128CmSha1_80 {
        hmac: Sha1,
        salt: aes_128_cm_sha1_80::RtpSalt,
        enc: aes_128_cm_sha1_80::Encrypter,
        dec: aes_128_cm_sha1_80::Decrypter,
    },
    AeadAes128Gcm {
        salt: aead_aes_128_gcm::RtpSalt,
        enc: aead_aes_128_gcm::Encrypter,
        dec: aead_aes_128_gcm::Decrypter,
    },
}

impl Derived {
    fn aes_128_cm_sha1_80(
        srtp_key: &SrtpKey<
            { aes_128_cm_sha1_80::MASTER_KEY_LEN },
            { aes_128_cm_sha1_80::MASTER_SALT_LEN },
        >,
    ) -> (Self, Self) {
        use aes_128_cm_sha1_80::*;

        // RTP AES Counter
        let mut rtp_aes = [0; MASTER_KEY_LEN];
        srtp_key.derive(LABEL_RTP_AES, &mut rtp_aes[..]);

        // RTP SHA1 HMAC
        let rtp_hmac = {
            let mut hmac = [0; HMAC_KEY_LEN];
            srtp_key.derive(LABEL_RTP_AUTHENTICATION_KEY, &mut hmac[..]);
            (&hmac[..]).into()
        };

        // RTP IV SALT
        let mut rtp_salt = [0; MASTER_SALT_LEN];
        srtp_key.derive(LABEL_RTP_SALT, &mut rtp_salt[..]);

        // RTCP AES Counter
        let mut rtcp_aes = [0; MASTER_KEY_LEN];
        srtp_key.derive(LABEL_RTCP_AES, &mut rtcp_aes[..]);

        // RTCP SHA1 HMAC
        let rtcp_hmac = {
            let mut hmac = [0; HMAC_KEY_LEN];
            srtp_key.derive(LABEL_RTCP_AUTHENTICATION_KEY, &mut hmac[..]);
            (&hmac[..]).into()
        };

        // RTCP IV SALT
        let mut rtcp_salt = [0; MASTER_SALT_LEN];
        srtp_key.derive(LABEL_RTCP_SALT, &mut rtcp_salt[..]);

        let rtp = Derived::Aes128CmSha1_80 {
            hmac: rtp_hmac,
            salt: rtp_salt,
            enc: Encrypter::new(rtp_aes),
            dec: Decrypter::new(rtp_aes),
        };

        let rtcp = Derived::Aes128CmSha1_80 {
            hmac: rtcp_hmac,
            salt: rtcp_salt,
            enc: Encrypter::new(rtcp_aes),
            dec: Decrypter::new(rtcp_aes),
        };

        (rtp, rtcp)
    }

    fn aead_aes_128_gcm(
        srtp_key: &SrtpKey<
            { aead_aes_128_gcm::MASTER_KEY_LEN },
            { aead_aes_128_gcm::MASTER_SALT_LEN },
        >,
    ) -> (Derived, Derived) {
        use aead_aes_128_gcm::*;

        // RTP session key
        let mut rtp_aes = [0; MASTER_KEY_LEN];
        srtp_key.derive(LABEL_RTP_AES, &mut rtp_aes[..]);

        // RTP session salt
        let mut rtp_salt = [0; MASTER_SALT_LEN];
        srtp_key.derive(LABEL_RTP_SALT, &mut rtp_salt[..]);

        // RTCP session key
        let mut rtcp_aes = [0; MASTER_KEY_LEN];
        srtp_key.derive(LABEL_RTCP_AES, &mut rtcp_aes[..]);

        // RTCP session salt
        let mut rtcp_salt = [0; MASTER_SALT_LEN];
        srtp_key.derive(LABEL_RTCP_SALT, &mut rtcp_salt[..]);

        let rtp = Derived::AeadAes128Gcm {
            salt: rtp_salt,
            enc: Encrypter::new(&rtp_aes),
            dec: Decrypter::new(&rtp_aes),
        };

        let rtcp = Derived::AeadAes128Gcm {
            salt: rtcp_salt,
            enc: Encrypter::new(&rtcp_aes),
            dec: Decrypter::new(&rtcp_aes),
        };

        (rtp, rtcp)
    }
}

impl fmt::Debug for Derived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Derived")
    }
}

// Implementation specific to `AES128_CM_SHA1_80`
mod aes_128_cm_sha1_80 {
    // SRTP_AES128_CM_HMAC_SHA1_80
    //    cipher: AES_128_CM
    //    cipher_key_length: 128
    //    cipher_salt_length: 112
    //    maximum_lifetime: 2^31
    //    auth_function: HMAC-SHA1
    //    auth_key_length: 160
    //    auth_tag_length: 80
    pub(super) const MASTER_KEY_LEN: usize = 16;
    pub(super) const MASTER_SALT_LEN: usize = 14;
    pub(super) const KEYING_MATERIAL_LEN: usize = MASTER_KEY_LEN * 2 + MASTER_SALT_LEN * 2;
    pub(super) const HMAC_KEY_LEN: usize = 20;
    pub(super) const HMAC_TAG_LEN: usize = 10;

    use std::fmt;

    use openssl::cipher;
    use openssl::cipher_ctx::CipherCtx;
    use openssl::error::ErrorStack;

    use crate::io::Sha1;

    type AesKey = [u8; 16];
    pub(super) type RtpSalt = [u8; 14];
    type RtpIv = [u8; 16];

    pub(super) struct Encrypter {
        ctx: CipherCtx,
    }

    impl Encrypter {
        pub(super) fn new(key: AesKey) -> Self {
            let t = cipher::Cipher::aes_128_ctr();
            let mut ctx = CipherCtx::new().expect("a reusable cipher context");
            ctx.encrypt_init(Some(t), Some(&key[..]), None)
                .expect("enc init");
            Encrypter { ctx }
        }

        pub(super) fn encrypt(
            &mut self,
            iv: &RtpIv,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<(), ErrorStack> {
            self.ctx.encrypt_init(None, None, Some(iv))?;
            let count = self.ctx.cipher_update(input, Some(output))?;
            self.ctx.cipher_final(&mut output[count..])?;
            Ok(())
        }
    }

    pub(super) struct Decrypter {
        ctx: CipherCtx,
    }

    impl Decrypter {
        pub(super) fn new(key: AesKey) -> Self {
            let t = cipher::Cipher::aes_128_ctr();
            let mut ctx = CipherCtx::new().expect("a reusable cipher context");
            ctx.decrypt_init(Some(t), Some(&key[..]), None)
                .expect("enc init");
            Decrypter { ctx }
        }

        pub(super) fn decrypt(
            &mut self,
            iv: &RtpIv,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<(), ErrorStack> {
            self.ctx.decrypt_init(None, None, Some(iv))?;
            let count = self.ctx.cipher_update(input, Some(output))?;
            self.ctx.cipher_final(&mut output[count..])?;
            Ok(())
        }
    }

    pub(super) trait RtpHmac {
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

            buf[hmac_start..(hmac_start + HMAC_TAG_LEN)].copy_from_slice(&tag[0..HMAC_TAG_LEN]);
        }

        fn rtp_verify(&self, buf: &[u8], srtp_index: u64, cmp: &[u8]) -> bool {
            let sha1 = self.clone();

            let roc = (srtp_index >> 16) as u32;

            let tag = sha1.hmac(&[buf, &roc.to_be_bytes()]);

            &tag[0..HMAC_TAG_LEN] == cmp
        }

        fn rtcp_hmac(&self, buf: &mut [u8], hmac_index: usize) {
            let sha1 = self.clone();

            let tag = sha1.hmac(&[&buf[0..hmac_index]]);

            buf[hmac_index..(hmac_index + HMAC_TAG_LEN)].copy_from_slice(&tag[0..HMAC_TAG_LEN]);
        }

        fn rtcp_verify(&self, buf: &[u8], cmp: &[u8]) -> bool {
            let sha1 = self.clone();

            let tag = sha1.hmac(&[buf]);

            &tag[0..HMAC_TAG_LEN] == cmp
        }
    }

    pub(super) trait ToRtpIv {
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
}

// Implementation specific to `AEAD_AES_128_GCM`
mod aead_aes_128_gcm {
    // +--------------------------------+------------------------------+
    // | Parameter                      | Value                        |
    // +--------------------------------+------------------------------+
    // | Master key length              | 128 bits                     |
    // | Master salt length             | 96 bits                      |
    // | Key Derivation Function        | AES_CM PRF(RFC3711)          |
    // | Maximum key lifetime (SRTP)    | 2^48 packets                 |
    // | Maximum key lifetime (SRTCP)   | 2^31 packets                 |
    // | Cipher (for SRTP and SRTCP)    | AEAD_AES_128_GCM             |
    // | AEAD authentication tag length | 128 bits                     |
    // +--------------------------------+------------------------------+

    use openssl::cipher;
    use openssl::cipher_ctx::CipherCtx;
    use openssl::error::ErrorStack;

    pub(super) const MASTER_KEY_LEN: usize = 16;
    pub(super) const MASTER_SALT_LEN: usize = 12;
    pub(super) const KEYING_MATERIAL_LEN: usize = MASTER_KEY_LEN * 2 + MASTER_SALT_LEN * 2;
    pub(super) const RTCP_AAD_LEN: usize = 12;
    pub(super) const TAG_LEN: usize = 16;
    const IV_LEN: usize = 12;

    type EncryptionKey = [u8; MASTER_KEY_LEN];
    type DecryptionKey = [u8; MASTER_KEY_LEN];
    pub(super) type RtpSalt = [u8; MASTER_SALT_LEN];
    type RtpIv = [u8; MASTER_SALT_LEN];

    pub(super) struct Encrypter {
        ctx: CipherCtx,
    }

    impl Encrypter {
        pub(super) fn new(key: &EncryptionKey) -> Self {
            let t = cipher::Cipher::aes_128_gcm();
            let mut ctx = CipherCtx::new().expect("a reusable cipher context");
            ctx.encrypt_init(Some(t), Some(key), None)
                .expect("enc init");
            ctx.set_iv_length(IV_LEN).expect("IV length");
            ctx.set_padding(false);

            Self { ctx }
        }

        pub(super) fn encrypt(
            &mut self,
            iv: &[u8; IV_LEN],
            aad: &[u8],
            input: &[u8],
            output: &mut [u8],
        ) -> Result<(), ErrorStack> {
            assert!(
                aad.len() >= 12,
                "Associated data length MUST be at least 12 octets"
            );

            // Set the IV
            self.ctx.encrypt_init(None, None, Some(iv))?;

            // Add the additional authenticated data, omitting the output argument informs
            // OpenSSL that we are providing AAD.
            let aad_c = self.ctx.cipher_update(aad, None)?;
            // TODO: This should maybe be an error
            assert!(aad_c == aad.len());

            let count = self.ctx.cipher_update(input, Some(output))?;
            let final_count = self.ctx.cipher_final(&mut output[count..])?;

            // Get the authentication tag and append it to the output
            let tag_offset = count + final_count;
            self.ctx
                .tag(&mut output[tag_offset..tag_offset + TAG_LEN])?;

            Ok(())
        }
    }

    pub(super) struct Decrypter {
        ctx: CipherCtx,
    }

    impl Decrypter {
        pub(super) fn new(key: &DecryptionKey) -> Self {
            let t = cipher::Cipher::aes_128_gcm();
            let mut ctx = CipherCtx::new().expect("a reusable cipher context");
            ctx.decrypt_init(Some(t), Some(key), None)
                .expect("dec init");

            Self { ctx }
        }

        pub(super) fn decrypt(
            &mut self,
            iv: &[u8; IV_LEN],
            aad: &[u8],
            input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, ErrorStack> {
            // This needs to be converted to an error maybe
            assert!(input.len() >= TAG_LEN);

            let (cipher_text, tag) = input.split_at(input.len() - TAG_LEN);
            self.ctx.decrypt_init(None, None, Some(iv))?;

            // Add the additional authenticated data, omitting the output argument informs
            // OpenSSL that we are providing AAD.
            // With this the authentication tag will be verified.
            self.ctx.cipher_update(aad, None)?;

            self.ctx.set_tag(tag)?;

            let count = self.ctx.cipher_update(cipher_text, Some(output))?;

            let final_count = self.ctx.cipher_final(&mut output[count..])?;

            Ok(count + final_count)
        }
    }

    pub(super) trait ToRtpIv {
        fn rtp_iv(&self, ssrc: u32, roc: u32, seq: u16) -> RtpIv;
        fn rtcp_iv(&self, ssrc: u32, srtp_index: u32) -> RtpIv;
    }

    impl ToRtpIv for RtpSalt {
        fn rtp_iv(&self, ssrc: u32, roc: u32, seq: u16) -> RtpIv {
            // See: https://www.rfc-editor.org/rfc/rfc7714#section-8.1

            // TODO: See if this is faster if rewritten for u128
            let mut iv = [0; MASTER_SALT_LEN];

            let ssrc_be = ssrc.to_be_bytes();
            let roc_be = roc.to_be_bytes();
            let seq_be = seq.to_be_bytes();

            iv[2..6].copy_from_slice(&ssrc_be);
            iv[6..10].copy_from_slice(&roc_be);
            iv[10..12].copy_from_slice(&seq_be);

            // XOR with salt
            for i in 0..MASTER_SALT_LEN {
                iv[i] ^= self[i];
            }

            iv
        }

        fn rtcp_iv(&self, ssrc: u32, srtp_index: u32) -> RtpIv {
            // See: https://www.rfc-editor.org/rfc/rfc7714#section-9.1
            // TODO: See if this is faster if rewritten for u128
            let mut iv = [0; MASTER_SALT_LEN];

            let ssrc_be = ssrc.to_be_bytes();
            let srtp_be = srtp_index.to_be_bytes();

            iv[2..6].copy_from_slice(&ssrc_be);
            iv[8..12].copy_from_slice(&srtp_be);

            // XOR with salt
            for i in 0..MASTER_SALT_LEN {
                iv[i] ^= self[i];
            }

            iv
        }
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

    mod test_aes128_cm_sha1_80 {
        use super::aes_128_cm_sha1_80::*;
        use super::*;

        const MAT: [u8; 60] = [
            0x2C, 0xB0, 0x23, 0x46, 0xB4, 0x22, 0x76, 0xA6, 0x72, 0xCF, 0xD1, 0x43, 0xAE, 0xC2,
            0xD5, 0xEE, 0xDD, 0xDE, 0x55, 0xF0, 0xAD, 0x7B, 0xCA, 0xC2, 0x26, 0x66, 0xF1, 0xC6,
            0x38, 0x61, 0x73, 0xED, 0x6E, 0xB2, 0x5C, 0xB7, 0xD2, 0x6A, 0x61, 0xA1, 0xEE, 0x2C,
            0x21, 0x0A, 0xDA, 0xE7, 0x60, 0xAA, 0xA2, 0xFD, 0x67, 0xB6, 0x72, 0xC4, 0x1A, 0xED,
            0x10, 0x5F, 0x9D, 0x36,
        ];

        const SRTCP: &[u8] = &[
            // header
            0x80, 0xC8, 0x00, 0x06, //
            // ssrc
            0x3C, 0xD7, 0xCC, 0x13, //
            // encrypted payload
            0xB7, 0xC8, 0x31, 0xDC, 0xB7, 0x76, 0xCD, 0x8D, 0xC2, 0x6F, 0xDA, 0x1D, 0x9B, 0xFC,
            0x8E, 0xE6, 0x58, 0x9A, 0x1A, 0x8A, 0x49, 0x28, 0x9C, 0xAE, 0xB2, 0x64, 0x20, 0x0C,
            0x37, 0xD2, 0xD0, 0xA4, 0xAF, 0xAC, 0x63, 0x85, 0xFF, 0xC6, 0x0D, 0xEC, 0x7D, 0x06,
            0xD4, 0x87, 0x3D, 0xD3, 0xA8, 0xCC, //
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
        fn unprotect_rtcp() {
            let key_mat = KeyingMaterial::new(MAT);
            let mut ctx_rx = SrtpProfile::Aes128CmSha1_80.create_context(&key_mat, true);

            let decrypted = ctx_rx.unprotect_rtcp(SRTCP).unwrap();

            // check srtcp_index will be 1
            assert_eq!(ctx_rx.srtcp_index, 0);
            // check srtcp_index in incoming was indeed 1
            let srtcp_index = SRTCP.len() - HMAC_TAG_LEN - SRTCP_INDEX_LEN;
            let e_and_i = &SRTCP[srtcp_index..(srtcp_index + 4)];
            assert_eq!(e_and_i, &0x8000_0001_u32.to_be_bytes());

            println!("{}", decrypted.len());
            println!("{decrypted:02x?}");

            // Take us back to where we started.
            let encrypted = ctx_rx.protect_rtcp(&decrypted);
            assert_eq!(encrypted, SRTCP);
        }
    }

    mod test_aead_aes_128_gcm {
        use super::aead_aes_128_gcm::*;

        mod rfc7714 {
            // Test vectors from RFC7714
            pub(super) const KEY: [u8; 16] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            ];

            /// Full plaintext RTP packet. First 12 octets is the header
            pub(super) const PLAINTEXT_RTP_PACKET: &[u8] = &[
                0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2, 0x47, 0x61,
                0x6c, 0x6c, 0x69, 0x61, 0x20, 0x65, 0x73, 0x74, 0x20, 0x6f, 0x6d, 0x6e, 0x69, 0x73,
                0x20, 0x64, 0x69, 0x76, 0x69, 0x73, 0x61, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x61, 0x72,
                0x74, 0x65, 0x73, 0x20, 0x74, 0x72, 0x65, 0x73,
            ];

            /// Full encrypted RTP packet. First 12 octets is the header.
            pub(super) const PROTECTED_RTP_PACKET: &[u8] = &[
                0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2, 0xf2, 0x4d,
                0xe3, 0xa3, 0xfb, 0x34, 0xde, 0x6c, 0xac, 0xba, 0x86, 0x1c, 0x9d, 0x7e, 0x4b, 0xca,
                0xbe, 0x63, 0x3b, 0xd5, 0x0d, 0x29, 0x4e, 0x6f, 0x42, 0xa5, 0xf4, 0x7a, 0x51, 0xc7,
                0xd1, 0x9b, 0x36, 0xde, 0x3a, 0xdf, 0x88, 0x33, 0x89, 0x9d, 0x7f, 0x27, 0xbe, 0xb1,
                0x6a, 0x91, 0x52, 0xcf, 0x76, 0x5e, 0xe4, 0x39, 0x0c, 0xce,
            ];

            pub(super) const RTP_IV: [u8; 12] = [
                0x51, 0x75, 0x3c, 0x65, 0x80, 0xc2, //
                0x72, 0x6f, 0x20, 0x71, 0x84, 0x14,
            ];

            // Full plaintext RTCP packet
            pub(super) const PLAINTEXT_RTCP_PACKET: &[u8] = &[
                0x81, 0xc8, 0x00, 0x0d, 0x4d, 0x61, 0x72, 0x73, 0x4e, 0x54, 0x50, 0x31, 0x4e, 0x54,
                0x50, 0x32, 0x52, 0x54, 0x50, 0x20, 0x00, 0x00, 0x04, 0x2a, 0x00, 0x00, 0xe9, 0x30,
                0x4c, 0x75, 0x6e, 0x61, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
                0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
            ];

            pub(super) const RTCP_PACKET_AAD: &[u8] = &[
                // First 8 octets from the RTCP header.
                0x81, 0xc8, 0x00, 0x0d, 0x4d, 0x61, 0x72, 0x73, //
                // SRTCP index + 31st bit(to indicate encryption)
                0x80, 0x00, 0x05, 0xd4,
            ];

            /// Full encrypted RTCP packet
            pub(super) const PROTECTED_RTCP_PACKET: &[u8] = &[
                0x63, 0xe9, 0x48, 0x85, 0xdc, 0xda, 0xb6, 0x7c, 0xa7, 0x27, 0xd7, 0x66, 0x2f, 0x6b,
                0x7e, 0x99, 0x7f, 0xf5, 0xc0, 0xf7, 0x6c, 0x06, 0xf3, 0x2d, 0xc6, 0x76, 0xa5, 0xf1,
                0x73, 0x0d, 0x6f, 0xda, 0x4c, 0xe0, 0x9b, 0x46, 0x86, 0x30, 0x3d, 0xed, 0x0b, 0xb9,
                0x27, 0x5b, 0xc8, 0x4a, 0xa4, 0x58, 0x96, 0xcf, 0x4d, 0x2f, 0xc5, 0xab, 0xf8, 0x72,
                0x45, 0xd9, 0xea, 0xde,
            ];

            pub(super) const RTCP_IV: [u8; 12] = [
                0x51, 0x75, 0x24, 0x05, 0x52, 0x03, //
                0x72, 0x6f, 0x20, 0x71, 0x70, 0xbb,
            ];
        }

        #[test]
        fn protect_rtp_rfc_7714_test() {
            let mut encrypter = Encrypter::new(&rfc7714::KEY);
            // first 12 octets contain the header
            let expected_len = rfc7714::PROTECTED_RTP_PACKET.len() - 12;
            let mut out = vec![0; expected_len];

            encrypter
                .encrypt(
                    &rfc7714::RTP_IV,
                    &rfc7714::PLAINTEXT_RTP_PACKET[..12],
                    &rfc7714::PLAINTEXT_RTP_PACKET[12..],
                    &mut out,
                )
                .expect("Should be able to encrypt");

            assert_eq!(out, rfc7714::PROTECTED_RTP_PACKET[12..]);
        }

        #[test]
        fn unprotect_rtp_rfc_7714_test() {
            let mut decrypter = Decrypter::new(&rfc7714::KEY);
            // The first 12 octets is the header and the 16 octet tag is also removed.
            let expected_len = rfc7714::PROTECTED_RTP_PACKET.len() - 12 - 16;
            let mut out = vec![0; expected_len];

            decrypter
                .decrypt(
                    &rfc7714::RTP_IV,
                    &rfc7714::PROTECTED_RTP_PACKET[..12],
                    &rfc7714::PROTECTED_RTP_PACKET[12..],
                    &mut out,
                )
                .expect("Should be able to decrypt");

            assert_eq!(out, rfc7714::PLAINTEXT_RTP_PACKET[12..]);
        }

        #[test]
        fn symmetry_rtp_rfc_7714_test() {
            // First we encrypt
            let mut encrypter = Encrypter::new(&rfc7714::KEY);
            // first 12 octets contain the header
            let expected_len = rfc7714::PROTECTED_RTP_PACKET.len() - 12;
            let mut cipher_text = vec![0; expected_len];

            encrypter
                .encrypt(
                    &rfc7714::RTP_IV,
                    &rfc7714::PLAINTEXT_RTP_PACKET[..12],
                    &rfc7714::PLAINTEXT_RTP_PACKET[12..],
                    &mut cipher_text,
                )
                .expect("Should be able to encrypt");

            // Then we decrypt the resulting cipher text
            let mut decrypter = Decrypter::new(&rfc7714::KEY);
            // The first 12 octets is the header and the 16 octet tag is also removed.
            let expected_len = rfc7714::PROTECTED_RTP_PACKET.len() - 12 - 16;
            let mut out = vec![0; expected_len];

            decrypter
                .decrypt(
                    &rfc7714::RTP_IV,
                    &rfc7714::PROTECTED_RTP_PACKET[..12],
                    &cipher_text,
                    &mut out,
                )
                .expect("Should be able to decrypt");

            // And verify we get the input back.
            assert_eq!(out, rfc7714::PLAINTEXT_RTP_PACKET[12..]);
        }

        #[test]
        fn protect_rtcp_rfc_7714_test() {
            let mut encrypter = Encrypter::new(&rfc7714::KEY);
            let expected_len = rfc7714::PROTECTED_RTCP_PACKET.len();
            let mut out = vec![0; expected_len];

            encrypter
                .encrypt(
                    &rfc7714::RTCP_IV,
                    rfc7714::RTCP_PACKET_AAD,
                    &rfc7714::PLAINTEXT_RTCP_PACKET[8..],
                    &mut out,
                )
                .expect("Should be able to encrypt");

            dbg!(out.len(), rfc7714::PROTECTED_RTCP_PACKET.len());
            assert!(
                out == rfc7714::PROTECTED_RTCP_PACKET,
                "Expected encrypted and tagged RTCP packet:\n{:02x?}\nGot:\n{:02x?}",
                rfc7714::PROTECTED_RTCP_PACKET,
                out
            );
        }

        #[test]
        fn unprotect_rtp_should_fail_with_broken_tag_data() {
            let mut decrypter = Decrypter::new(&rfc7714::KEY);
            // The first 12 octets is the header and the 16 octet tag is also removed.
            let expected_len = rfc7714::PROTECTED_RTP_PACKET.len() - 12 - 16;
            let mut out = vec![0; expected_len];
            let header = {
                let mut header = rfc7714::PROTECTED_RTP_PACKET[..12].to_vec();
                // Mess with part of the sequence number, since this makes up part of the
                // authenticated additional data(AAD) the resulting authenticity tag should not
                // match.
                header[3] ^= 0xFF;

                header
            };

            let result = decrypter.decrypt(
                &rfc7714::RTP_IV,
                &header,
                &rfc7714::PROTECTED_RTP_PACKET[12..],
                &mut out,
            );
            assert!(result.is_err(), "Should fail to decrypt a SRTP packet that has mismatched authenicated additional data");
        }

        #[test]
        fn unprotect_rtp_should_fail_with_broken_null_tag() {
            let mut decrypter = Decrypter::new(&rfc7714::KEY);
            // The first 12 octets is the header and the 16 octet tag is also removed.
            let expected_len = rfc7714::PROTECTED_RTP_PACKET.len() - 12 - 16;
            let input = {
                let mut input = rfc7714::PROTECTED_RTP_PACKET.to_vec();
                let len = input.len();
                input[len - TAG_LEN..].copy_from_slice(&[0; TAG_LEN]);

                input
            };
            let mut out = vec![0; expected_len];

            let result = decrypter.decrypt(
                &rfc7714::RTP_IV,
                rfc7714::RTCP_PACKET_AAD,
                &input[12..],
                &mut out,
            );
            assert!(result.is_err(), "Should fail to decrypt a SRTP packet that has mismatched authenicated additional data");
        }
    }
}
