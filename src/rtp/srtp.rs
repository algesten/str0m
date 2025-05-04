use std::fmt;

use crate::crypto::{aead_aes_128_gcm, aes_128_cm_sha1_80, SrtpProfile};
use crate::crypto::{KeyingMaterial, SrtpCrypto};

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

impl SrtpContext {
    /// Create an SRTP context for the relevant profile using the provided keying material.
    pub fn new(
        crypto: &SrtpCrypto,
        profile: SrtpProfile,
        mat: &KeyingMaterial,
        left: bool,
    ) -> Self {
        match profile {
            #[cfg(feature = "_internal_test_exports")]
            SrtpProfile::PassThrough => SrtpContext {
                rtp: Derived::PassThrough,
                rtcp: Derived::PassThrough,
                srtcp_index: 0,
            },
            SrtpProfile::Aes128CmSha1_80 => {
                use aes_128_cm_sha1_80::{KEY_LEN, SALT_LEN};

                let key = SrtpKey::<KEY_LEN, SALT_LEN>::new(mat, left);

                let (rtp, rtcp) = Derived::aes_128_cm_sha1_80(crypto, &key);

                SrtpContext {
                    rtp,
                    rtcp,
                    srtcp_index: 0,
                }
            }
            SrtpProfile::AeadAes128Gcm => {
                use aead_aes_128_gcm::{KEY_LEN, SALT_LEN};

                let key = SrtpKey::<KEY_LEN, SALT_LEN>::new(mat, left);

                let (rtp, rtcp) = Derived::aead_aes_128_gcm(crypto, &key);

                SrtpContext {
                    rtp,
                    rtcp,
                    srtcp_index: 0,
                }
            }
        }
    }

    #[cfg(test)]
    fn new_aead_aes_128_gcm(
        rtp_key: [u8; aead_aes_128_gcm::KEY_LEN],
        rtp_salt: [u8; aead_aes_128_gcm::SALT_LEN],
        rtcp_key: [u8; aead_aes_128_gcm::KEY_LEN],
        rtcp_salt: [u8; aead_aes_128_gcm::SALT_LEN],
        srtcp_index: u32,
    ) -> Self {
        let crypto = crate::CryptoProvider::from_feature_flags().srtp_crypto();

        Self {
            rtp: Derived::AeadAes128Gcm {
                salt: rtp_salt,
                enc: crypto.new_aead_aes_128_gcm(rtp_key, true),
                dec: crypto.new_aead_aes_128_gcm(rtp_key, false),
            },
            rtcp: Derived::AeadAes128Gcm {
                salt: rtcp_salt,
                enc: crypto.new_aead_aes_128_gcm(rtcp_key, true),
                dec: crypto.new_aead_aes_128_gcm(rtcp_key, false),
            },
            srtcp_index,
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
        // SRTP layout
        // [header, [rtp, (padding + pad_count)], tag]

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
        let hlen = header.header_len;
        let input = &buf[hlen..];

        match &mut self.rtp {
            #[cfg(feature = "_internal_test_exports")]
            Derived::PassThrough => input.to_vec(),
            Derived::Aes128CmSha1_80 { key, salt, enc, .. } => {
                assert!(
                    input.len() % SRTP_BLOCK_SIZE == 0,
                    "RTP body should be padded to 16 byte block size, {header:?} with \
                    body length {} was not",
                    input.len()
                );
                use aes_128_cm_sha1_80::HMAC_TAG_LEN;

                let iv = aes_128_cm_sha1_80::rtp_iv(*salt, *header.ssrc, srtp_index);

                let mut output = vec![0_u8; buf.len() + HMAC_TAG_LEN];
                enc.encrypt(&iv, input, &mut output[hlen..])
                    .expect("rtp encrypt");

                output[..hlen].copy_from_slice(&buf[..hlen]);

                let hmac_start = buf.len();
                aes_128_cm_sha1_80::rtp_hmac(key, &mut output, srtp_index, hmac_start);

                output
            }
            Derived::AeadAes128Gcm { salt, enc, .. } => {
                use aead_aes_128_gcm::TAG_LEN;
                let roc = (srtp_index >> 16) as u32;

                let iv = aead_aes_128_gcm::rtp_iv(*salt, *header.ssrc, roc, header.sequence_number);
                let aad = &buf[..hlen];

                // Input and output lengths for encryption:
                // https://www.rfc-editor.org/rfc/rfc7714#section-5.2.1
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
            #[cfg(feature = "_internal_test_exports")]
            Derived::PassThrough => Some(buf.to_vec()),
            Derived::Aes128CmSha1_80 { key, salt, dec, .. } => {
                use aes_128_cm_sha1_80::HMAC_TAG_LEN;

                if buf.len() < HMAC_TAG_LEN {
                    return None;
                }

                let hmac_start = buf.len() - HMAC_TAG_LEN;

                if !aes_128_cm_sha1_80::rtp_verify(
                    key,
                    &buf[..hmac_start],
                    srtp_index,
                    &buf[hmac_start..],
                ) {
                    trace!("unprotect_rtp hmac verify fail");
                    return None;
                }

                let iv = aes_128_cm_sha1_80::rtp_iv(*salt, *header.ssrc, srtp_index);

                let input = &buf[header.header_len..hmac_start];
                let mut output = vec![0; input.len()];

                if let Err(e) = dec.decrypt(&iv, input, &mut output) {
                    warn!(
                        "Failed to decrypt SRTP {} ({}): {}",
                        self.rtp.profile(),
                        error_details(header, srtp_index),
                        e
                    );
                    return None;
                };

                Some(output)
            }
            Derived::AeadAes128Gcm { salt, dec, .. } => {
                use aead_aes_128_gcm::TAG_LEN;

                if buf.len() < TAG_LEN {
                    return None;
                }

                let roc: u32 = (srtp_index >> 16) as u32;
                let seq = header.sequence_number;

                let iv = aead_aes_128_gcm::rtp_iv(*salt, *header.ssrc, roc, seq);

                let (aad, input) = buf.split_at(header.header_len);
                // Input and output lengths for decryption:
                // https://www.rfc-editor.org/rfc/rfc7714#section-5.2.2
                let mut output = vec![0; input.len() - TAG_LEN];

                match dec.decrypt(&iv, &[aad], input, &mut output) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                            "Failed to decrypt SRTP {} ({}): {}",
                            self.rtp.profile(),
                            error_details(header, srtp_index),
                            e
                        );
                        return None;
                    }
                };

                Some(output)
            }
        }
    }

    pub fn protect_rtcp(&mut self, buf: &[u8]) -> Vec<u8> {
        let srtcp_index = self.srtcp_index;

        // https://tools.ietf.org/html/rfc3711#page-15
        // The SRTCP index MUST be set to zero before the first SRTCP
        // packet is sent, and MUST be incremented by one,
        // modulo 2^31, after each SRTCP packet is sent.
        self.srtcp_index = (self.srtcp_index + 1) % 2_u32.pow(31);

        // e is always encrypted, rest is 31 byte index.
        let e_and_si = 0x8000_0000 | srtcp_index;
        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        if ssrc == 0 {
            warn!("SSRC 0 does not make a good SRTCP IV");
        }

        match &mut self.rtcp {
            #[cfg(feature = "_internal_test_exports")]
            Derived::PassThrough => buf.to_vec(),
            Derived::Aes128CmSha1_80 { key, salt, enc, .. } => {
                use aes_128_cm_sha1_80::HMAC_TAG_LEN;

                let iv = aes_128_cm_sha1_80::rtp_iv(*salt, ssrc, srtcp_index as u64);

                let mut output = vec![0_u8; buf.len() + SRTCP_INDEX_LEN + HMAC_TAG_LEN];
                output[0..8].copy_from_slice(&buf[0..8]);
                let input = &buf[8..];
                let encout = &mut output[8..(8 + input.len())];

                enc.encrypt(&iv, input, encout).expect("rtcp encrypt");

                let to = &mut output[buf.len()..];
                to[0..4].copy_from_slice(&e_and_si.to_be_bytes());

                let hmac_index = output.len() - HMAC_TAG_LEN;
                aes_128_cm_sha1_80::rtcp_hmac(key, &mut output, hmac_index);

                output
            }
            Derived::AeadAes128Gcm { salt, enc, .. } => {
                use aead_aes_128_gcm::{RTCP_AAD_LEN, TAG_LEN};
                let iv = aead_aes_128_gcm::rtcp_iv(*salt, ssrc, srtcp_index);

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

    // SRTCP layout
    // ["header", ssrc, payload, ["header", ssrc, payload], ...], ssrtcp_index, tag]
    //
    // |----------------------------------------------------------------------|
    //                          authenticated
    //
    //                  |--------------------------------------|
    //                              encrypted (aes)
    pub fn unprotect_rtcp(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        match &mut self.rtcp {
            #[cfg(feature = "_internal_test_exports")]
            Derived::PassThrough => Some(buf.to_vec()),
            Derived::Aes128CmSha1_80 { key, salt, dec, .. } => {
                use aes_128_cm_sha1_80::HMAC_TAG_LEN;

                if buf.len() < HMAC_TAG_LEN + SRTCP_INDEX_LEN {
                    return None;
                }

                let hmac_start = buf.len() - HMAC_TAG_LEN;

                if !aes_128_cm_sha1_80::rtcp_verify(key, &buf[..hmac_start], &buf[hmac_start..]) {
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

                let iv = aes_128_cm_sha1_80::rtp_iv(*salt, ssrc, srtcp_index as u64);

                // The Encrypted Portion of an SRTCP packet consists of the encryption
                // of the RTCP payload of the equivalent compound RTCP packet, from the
                // first RTCP packet, i.e., from the ninth (9) octet to the end of the
                // compound packet.
                let input = &buf[8..idx_start];
                let mut output = vec![0_u8; input.len() + 8];
                output[0..8].copy_from_slice(&buf[0..8]);

                if let Err(e) = dec.decrypt(&iv, input, &mut output[8..]) {
                    warn!("Failed to decrypt SRTCP {}: {}", self.rtcp.profile(), e);
                    return None;
                }

                Some(output)
            }
            Derived::AeadAes128Gcm { salt, dec, .. } => {
                use aead_aes_128_gcm::{RTCP_AAD_LEN, TAG_LEN};

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

                // The Encrypted Portion of an SRTCP packet consists of the encryption
                // of the RTCP payload of the equivalent compound RTCP packet, from the
                // first RTCP packet, i.e., from the ninth (9) octet to the end of the
                // compound packet.
                let input = if is_encrypted {
                    &buf[8..idx_start]
                } else {
                    // No, encryption but we still pass the tag down to decrypt so it can verify
                    // it.
                    &buf[idx_start - TAG_LEN..idx_start]
                };

                // The SRTCP index is a 31-bit counter for the SRTCP packet.
                let srtcp_index = e_and_si & 0x7fff_ffff;
                let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

                let iv = aead_aes_128_gcm::rtcp_iv(*salt, ssrc, srtcp_index);
                // Declared out here for lifetime purposes, only used in the first branch of the if.
                let mut encrypted_aad = [0; RTCP_AAD_LEN];
                let mut aads: [&[u8]; 2] = [&[], &[]];

                if is_encrypted {
                    encrypted_aad[0..8].copy_from_slice(&buf[0..8]);
                    encrypted_aad[8..12].copy_from_slice(&e_and_si.to_be_bytes());

                    aads[0] = encrypted_aad.as_slice();
                } else {
                    // The whole packet is AAD
                    aads[0] = &buf[0..idx_start - TAG_LEN];
                    aads[1] = &buf[idx_start..];
                };

                let mut output = vec![0_u8; buf.len() - TAG_LEN - SRTCP_INDEX_LEN];
                output[0..8].copy_from_slice(&buf[0..8]);

                let count = match dec.decrypt(&iv, &aads, input, &mut output[8..]) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Failed to decrypt SRTCP {}: {}", self.rtcp.profile(), e);
                        return None;
                    }
                };

                if is_encrypted {
                    output.truncate(8 + count);
                } else {
                    // decrypt didn't error, the data is authenticated.
                    output.copy_from_slice(&buf[0..buf.len() - SRTCP_INDEX_LEN - TAG_LEN])
                }

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

    fn derive(&self, crypto: &SrtpCrypto, label: u8, out: &mut [u8]) {
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
            crypto.srtp_aes_128_ecb_round(&self.master, &input[..], &mut buf[..]);

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
    #[cfg(feature = "_internal_test_exports")]
    PassThrough,
    Aes128CmSha1_80 {
        key: [u8; 20],
        salt: aes_128_cm_sha1_80::RtpSalt,
        enc: Box<dyn aes_128_cm_sha1_80::CipherCtx>,
        dec: Box<dyn aes_128_cm_sha1_80::CipherCtx>,
    },
    AeadAes128Gcm {
        salt: aead_aes_128_gcm::RtpSalt,
        enc: Box<dyn aead_aes_128_gcm::CipherCtx>,
        dec: Box<dyn aead_aes_128_gcm::CipherCtx>,
    },
}

impl Derived {
    fn aes_128_cm_sha1_80(
        crypto: &SrtpCrypto,
        srtp_key: &SrtpKey<{ aes_128_cm_sha1_80::KEY_LEN }, { aes_128_cm_sha1_80::SALT_LEN }>,
    ) -> (Self, Self) {
        use aes_128_cm_sha1_80::*;

        // RTP AES Counter
        let mut rtp_aes = [0; KEY_LEN];
        srtp_key.derive(crypto, LABEL_RTP_AES, &mut rtp_aes[..]);

        // RTP SHA1 HMAC
        let rtp_hmac = {
            let mut hmac = [0; HMAC_KEY_LEN];
            srtp_key.derive(crypto, LABEL_RTP_AUTHENTICATION_KEY, &mut hmac[..]);
            hmac
        };

        // RTP IV SALT
        let mut rtp_salt = [0; SALT_LEN];
        srtp_key.derive(crypto, LABEL_RTP_SALT, &mut rtp_salt[..]);

        // RTCP AES Counter
        let mut rtcp_aes = [0; KEY_LEN];
        srtp_key.derive(crypto, LABEL_RTCP_AES, &mut rtcp_aes[..]);

        // RTCP SHA1 HMAC
        let rtcp_hmac = {
            let mut hmac = [0; HMAC_KEY_LEN];
            srtp_key.derive(crypto, LABEL_RTCP_AUTHENTICATION_KEY, &mut hmac[..]);
            hmac
        };

        // RTCP IV SALT
        let mut rtcp_salt = [0; SALT_LEN];
        srtp_key.derive(crypto, LABEL_RTCP_SALT, &mut rtcp_salt[..]);

        let rtp = Derived::Aes128CmSha1_80 {
            key: rtp_hmac,
            salt: rtp_salt,
            enc: crypto.new_aes_128_cm_sha1_80(rtp_aes, true),
            dec: crypto.new_aes_128_cm_sha1_80(rtp_aes, false),
        };

        let rtcp = Derived::Aes128CmSha1_80 {
            key: rtcp_hmac,
            salt: rtcp_salt,
            enc: crypto.new_aes_128_cm_sha1_80(rtcp_aes, true),
            dec: crypto.new_aes_128_cm_sha1_80(rtcp_aes, false),
        };

        (rtp, rtcp)
    }

    fn aead_aes_128_gcm(
        crypto: &SrtpCrypto,
        srtp_key: &SrtpKey<{ aead_aes_128_gcm::KEY_LEN }, { aead_aes_128_gcm::SALT_LEN }>,
    ) -> (Derived, Derived) {
        use aead_aes_128_gcm::*;

        // RTP session key
        let mut rtp_aes = [0; KEY_LEN];
        srtp_key.derive(crypto, LABEL_RTP_AES, &mut rtp_aes[..]);

        // RTP session salt
        let mut rtp_salt = [0; SALT_LEN];
        srtp_key.derive(crypto, LABEL_RTP_SALT, &mut rtp_salt[..]);

        // RTCP session key
        let mut rtcp_aes = [0; KEY_LEN];
        srtp_key.derive(crypto, LABEL_RTCP_AES, &mut rtcp_aes[..]);

        // RTCP session salt
        let mut rtcp_salt = [0; SALT_LEN];
        srtp_key.derive(crypto, LABEL_RTCP_SALT, &mut rtcp_salt[..]);

        let rtp = Derived::AeadAes128Gcm {
            salt: rtp_salt,
            enc: crypto.new_aead_aes_128_gcm(rtp_aes, true),
            dec: crypto.new_aead_aes_128_gcm(rtp_aes, false),
        };

        let rtcp = Derived::AeadAes128Gcm {
            salt: rtcp_salt,
            enc: crypto.new_aead_aes_128_gcm(rtcp_aes, true),
            dec: crypto.new_aead_aes_128_gcm(rtcp_aes, false),
        };

        (rtp, rtcp)
    }

    fn profile(&self) -> SrtpProfile {
        match self {
            #[cfg(feature = "_internal_test_exports")]
            Derived::PassThrough => SrtpProfile::PassThrough,
            Derived::Aes128CmSha1_80 { .. } => SrtpProfile::Aes128CmSha1_80,
            Derived::AeadAes128Gcm { .. } => SrtpProfile::AeadAes128Gcm,
        }
    }
}

impl fmt::Debug for Derived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Derived")
    }
}

fn error_details(header: &RtpHeader, srtp_index: u64) -> String {
    format!(
        "SSRC: {} seq_no: {} pt: {} mid: {:?} rid: {:?} rid_repair: {:?} srtp_index: {}",
        header.ssrc,
        header.sequence_number,
        header.payload_type,
        header.ext_vals.mid,
        header.ext_vals.rid,
        header.ext_vals.rid_repair,
        srtp_index
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn derive_key() {
        crate::init_crypto_default();
        let crypto = crate::CryptoProvider::from_feature_flags().srtp_crypto();

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
        sk.derive(&crypto, 0, &mut out[..]);

        assert_eq!(
            out,
            [
                0xC6, 0x1E, 0x7A, 0x93, 0x74, 0x4F, 0x39, 0xEE, //
                0x10, 0x73, 0x4A, 0xFE, 0x3F, 0xF7, 0xA0, 0x87
            ]
        );

        // hmac
        let mut out = [0_u8; 20];
        sk.derive(&crypto, 1, &mut out[..]);

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
        sk.derive(&crypto, 2, &mut out[..]);

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

        const DECRYPTED_PAYLOAD: &[u8] = &[
            0x80, 0xc8, 0x00, 0x06, 0x3c, 0xd7, 0xcc, 0x13, 0xe2, 0xee, 0x35, 0xc8, 0x60, 0x4e,
            0x61, 0x8c, 0x26, 0xf3, 0x27, 0x34, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x14, 0x07,
            0x81, 0xca, 0x00, 0x06, 0x3c, 0xd7, 0xcc, 0x13, 0x01, 0x10, 0x38, 0x6e, 0x46, 0x75,
            0x32, 0x68, 0x57, 0x66, 0x72, 0x4d, 0x44, 0x72, 0x47, 0x66, 0x34, 0x6f, 0x00, 0x00,
        ];

        #[test]
        fn unprotect_rtcp() {
            let key_mat = KeyingMaterial::new(MAT.to_vec());
            let crypto = crate::CryptoProvider::from_feature_flags().srtp_crypto();
            let mut ctx_rx =
                SrtpContext::new(&crypto, SrtpProfile::Aes128CmSha1_80, &key_mat, true);
            ctx_rx.srtcp_index = 1;

            let decrypted = ctx_rx.unprotect_rtcp(SRTCP).unwrap();

            assert_eq!(ctx_rx.srtcp_index, 1);
            // check srtcp_index in incoming was indeed 1
            let srtcp_index = SRTCP.len() - HMAC_TAG_LEN - SRTCP_INDEX_LEN;
            let e_and_i = &SRTCP[srtcp_index..(srtcp_index + 4)];
            assert_eq!(e_and_i, &0x8000_0001_u32.to_be_bytes());
            assert_eq!(decrypted, DECRYPTED_PAYLOAD);

            // Take us back to where we started.
            let encrypted = ctx_rx.protect_rtcp(&decrypted);
            assert_eq!(encrypted, SRTCP);
        }
    }

    mod test_aead_aes_128_gcm {
        use crate::rtp_::ExtensionMap;

        use super::*;

        use super::aead_aes_128_gcm::*;

        mod rfc7714 {
            // Test vectors from RFC7714

            // Session Key (RTP and RTCP)
            pub(super) const KEY: [u8; 16] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            ];

            // Session Salt (RTP and RTCP)
            pub(super) const SALT: [u8; 12] = [
                0x51, 0x75, 0x69, 0x64, 0x20, 0x70, 0x72, 0x6f, 0x20, 0x71, 0x75, 0x6f,
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

            // Full plaintext RTCP packet
            pub(super) const PLAINTEXT_RTCP_PACKET: &[u8] = &[
                0x81, 0xc8, 0x00, 0x0d, 0x4d, 0x61, 0x72, 0x73, 0x4e, 0x54, 0x50, 0x31, 0x4e, 0x54,
                0x50, 0x32, 0x52, 0x54, 0x50, 0x20, 0x00, 0x00, 0x04, 0x2a, 0x00, 0x00, 0xe9, 0x30,
                0x4c, 0x75, 0x6e, 0x61, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
                0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
            ];

            /// Full encrypted RTCP packet
            pub(super) const PROTECTED_RTCP_PACKET: &[u8] = &[
                0x81, 0xc8, 0x00, 0x0d, 0x4d, 0x61, 0x72, 0x73, 0x63, 0xe9, 0x48, 0x85, 0xdc, 0xda,
                0xb6, 0x7c, 0xa7, 0x27, 0xd7, 0x66, 0x2f, 0x6b, 0x7e, 0x99, 0x7f, 0xf5, 0xc0, 0xf7,
                0x6c, 0x06, 0xf3, 0x2d, 0xc6, 0x76, 0xa5, 0xf1, 0x73, 0x0d, 0x6f, 0xda, 0x4c, 0xe0,
                0x9b, 0x46, 0x86, 0x30, 0x3d, 0xed, 0x0b, 0xb9, 0x27, 0x5b, 0xc8, 0x4a, 0xa4, 0x58,
                0x96, 0xcf, 0x4d, 0x2f, 0xc5, 0xab, 0xf8, 0x72, 0x45, 0xd9, 0xea, 0xde, 0x80, 0x00,
                0x05, 0xd4,
            ];

            // A RTCP packet that hasn't been encrypted, only authenticated.
            pub(super) const TAGGED_RTCP_PACKET: &[u8] = &[
                // RTCP Packet
                0x81, 0xc8, 0x00, 0x0d, 0x4d, 0x61, 0x72, 0x73, 0x4e, 0x54, 0x50, 0x31, 0x4e, 0x54,
                0x50, 0x32, 0x52, 0x54, 0x50, 0x20, 0x00, 0x00, 0x04, 0x2a, 0x00, 0x00, 0xe9, 0x30,
                0x4c, 0x75, 0x6e, 0x61, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
                0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, //
                // Tag
                0x84, 0x1d, 0xd9, 0x68, 0x3d, 0xd7, 0x8e, 0xc9, 0x2a, 0xe5, 0x87, 0x90, 0x12, 0x5f,
                0x62, 0xb3, //
                // SRTCP Index
                0x00, 0x00, 0x05, 0xd4,
            ];
        }

        #[test]
        fn protect_rtp_rfc_7714_test() {
            let mut context = make_rtp_context();

            let header =
                RtpHeader::parse(&rfc7714::PLAINTEXT_RTP_PACKET[..12], &ExtensionMap::empty())
                    .expect("header to parse");
            let out = context.protect_rtp(rfc7714::PLAINTEXT_RTP_PACKET, &header, 0);

            assert_eq!(
                out,
                rfc7714::PROTECTED_RTP_PACKET,
                "failed to encrypted packet.\n{:02x?}\n{:02x?}",
                out,
                &rfc7714::PLAINTEXT_RTP_PACKET
            );
        }

        #[test]
        fn unprotect_rtp_rfc_7714_test() {
            let mut context = make_rtp_context();
            let header =
                RtpHeader::parse(&rfc7714::PROTECTED_RTP_PACKET[..12], &ExtensionMap::empty())
                    .expect("header to parse");

            let out = context
                .unprotect_rtp(rfc7714::PROTECTED_RTP_PACKET, &header, 0)
                .expect("decrypt rtp");

            assert_eq!(
                out,
                rfc7714::PLAINTEXT_RTP_PACKET[12..],
                "failed to decrypt packet.\n{:02x?}\n{:02x?}",
                out,
                &rfc7714::PLAINTEXT_RTP_PACKET
            );
        }

        #[test]
        fn symmetry_rtp_rfc_7714_test() {
            let mut context = make_rtp_context();

            // First we encrypt
            let header =
                RtpHeader::parse(&rfc7714::PLAINTEXT_RTP_PACKET[..12], &ExtensionMap::empty())
                    .expect("header to parse");
            let encrypted = context.protect_rtp(rfc7714::PLAINTEXT_RTP_PACKET, &header, 0);

            // Then we decrypt the resulting cipher text
            let header = RtpHeader::parse(&encrypted[..12], &ExtensionMap::empty())
                .expect("header to parse");
            let decrypted = context
                .unprotect_rtp(&encrypted, &header, 0)
                .expect("rtp unprotect");

            // And verify we get the input back.
            assert_eq!(decrypted, rfc7714::PLAINTEXT_RTP_PACKET[12..]);
        }

        #[test]
        fn unprotect_rtp_should_fail_with_broken_tag_data() {
            let mut context = make_rtp_context();

            let header_buf = {
                let mut buf = rfc7714::PROTECTED_RTP_PACKET[..12].to_vec();
                // Mess with part of the sequence number, since this makes up part of the
                // authenticated additional data(AAD) the resulting authenticity tag should not
                // match.
                buf[3] ^= 0xFF;

                buf
            };

            let header =
                RtpHeader::parse(&header_buf, &ExtensionMap::empty()).expect("header to parse");

            let result = context.unprotect_rtp(rfc7714::PROTECTED_RTP_PACKET, &header, 0);
            assert!(
                result.is_none(),
                "Should fail to decrypt a SRTP packet that has mismatched \
                authenicated additional data"
            );
        }

        #[test]
        fn unprotect_rtp_should_fail_with_broken_null_tag() {
            let mut context = make_rtp_context();

            let input = {
                let mut input = rfc7714::PROTECTED_RTP_PACKET.to_vec();
                let len = input.len();
                input[len - TAG_LEN..].copy_from_slice(&[0; TAG_LEN]);

                input
            };

            let header =
                RtpHeader::parse(&input[..12], &ExtensionMap::empty()).expect("header to parse");

            let result = context.unprotect_rtp(&input, &header, 0);
            assert!(
                result.is_none(),
                "Should fail to decrypt a SRTP packet with null tag"
            );
        }

        #[test]
        fn protect_rtcp_rfc_7714_test() {
            let mut context = make_rtcp_context();

            let out = context.protect_rtcp(rfc7714::PLAINTEXT_RTCP_PACKET);

            assert!(
                out == rfc7714::PROTECTED_RTCP_PACKET,
                "Expected encrypted and tagged RTCP packet:\n{:02x?}\nGot:\n{:02x?}",
                rfc7714::PROTECTED_RTCP_PACKET,
                out
            );
        }

        #[test]
        fn unprotect_rtcp_rfc_auth_only_7714_test() {
            let mut context = make_rtcp_context();

            let out = context
                .unprotect_rtcp(rfc7714::TAGGED_RTCP_PACKET)
                .expect("Unprotect RTCP");

            assert_eq!(out, rfc7714::PLAINTEXT_RTCP_PACKET);
        }

        fn make_rtp_context() -> SrtpContext {
            crate::init_crypto_default();
            SrtpContext::new_aead_aes_128_gcm(
                rfc7714::KEY,
                rfc7714::SALT,
                rfc7714::KEY,
                rfc7714::SALT,
                0,
            )
        }

        fn make_rtcp_context() -> SrtpContext {
            crate::init_crypto_default();
            SrtpContext::new_aead_aes_128_gcm(
                rfc7714::KEY,
                rfc7714::SALT,
                rfc7714::KEY,
                rfc7714::SALT,
                0x000005d4,
            )
        }
    }
}
