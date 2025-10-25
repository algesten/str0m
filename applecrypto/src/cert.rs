use std::ffi::c_void;

use crate::apple_common_crypto::{CC_SHA256, CC_SHA256_DIGEST_LENGTH};

use super::AppleCryptoError;
//use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use security_framework::certificate::SecCertificate;
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey};

#[derive(Debug)]
pub struct Certificate {
    certificate: SecCertificate,
}

impl Certificate {
    pub fn new_self_signed(
        _use_ec_dsa_keys: bool,
        subject: &str,
    ) -> Result<Self, AppleCryptoError> {
        // OIDs
        let rsa_encryption = oid(&[1, 2, 840, 113549, 1, 1, 1]);
        let sha256_with_rsa = oid(&[1, 2, 840, 113549, 1, 1, 11]);
        let common_name = oid(&[2, 5, 4, 3]);
        let basic_constraints = oid(&[2, 5, 29, 19]);

        // 1. Generate RSA-2048 key pair
        let mut key_options = GenerateKeyOptions::default();
        key_options.set_key_type(KeyType::rsa());
        key_options.set_size_in_bits(2048);
        let key = SecKey::new(&key_options)?;
        let public_key = key.public_key().unwrap();
        println!("{key:?} {public_key:?}");
        // 2. Export public key as DER (SPKI)
        let spki_der = public_key.external_representation().unwrap();
        let spki = sequence(&[
            sequence(&[rsa_encryption, tag(0x05, &[])]), // NULL
            bit_string(&spki_der),
        ]);

        // 3. Build TBSCertificate
        let serial = integer(1);
        let sig_alg = sequence(&[sha256_with_rsa.clone(), tag(0x05, &[])]);
        let issuer = sequence(&[set(&[sequence(&[
            common_name.clone(),
            utf8_string(subject),
        ])])]);
        let subject = issuer.clone();

        let now = Utc::now();
        let not_before = generalized_time(now);
        let not_after = generalized_time(now + Duration::days(365));

        let validity = sequence(&[not_before, not_after]);

        // basicConstraints: critical, CA:TRUE
        let bc_value = sequence(&[vec![0x01, 0x01, 0x00]]); // BOOLEAN TRUE
        let bc_ext = sequence(&[
            basic_constraints,
            vec![0x01, 0x01, 0xFF], // critical
            bc_value,
        ]);
        let extensions = tag(0xA0, &sequence(&[bc_ext])); // [3] EXPLICIT

        let tbs = sequence(&[
            tag(0xA0, &sequence(&[vec![0x02, 0x01, 0x02]])), // version v3
            serial,
            sig_alg.clone(),
            issuer,
            validity,
            subject,
            spki,
            extensions,
        ]);

        // 4. SHA-256 hash of TBS
        let mut hash = [0u8; CC_SHA256_DIGEST_LENGTH];
        unsafe {
            CC_SHA256(
                tbs.as_ptr() as *const c_void,
                tbs.len() as u32,
                hash.as_mut_ptr(),
            )
        };

        // 5. Sign hash with private key
        let signature = key.create_signature(Algorithm::RSASignatureDigestPKCS1v15SHA256, &hash)?;

        // 6. Full Certificate
        let cert_der = sequence(&[tbs, sig_alg, bit_string(&signature)]);

        // 7. Create SecCertificate
        let certificate = SecCertificate::from_der(&cert_der).unwrap();

        Ok(Self { certificate })
    }

    pub fn sha256_fingerprint(&self) -> Result<[u8; 32], AppleCryptoError> {
        todo!();
    }
}

/// Helper: Encode ASN.1 length
fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = len.to_be_bytes().to_vec();
        while bytes[0] == 0 {
            bytes.remove(0);
        }
        let count = bytes.len();
        let mut out = vec![0x80 | count as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

/// Helper: ASN.1 tag
fn tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Helper: ASN.1 INTEGER
fn integer(n: i64) -> Vec<u8> {
    let mut bytes = n.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tag(0x02, &bytes)
}

/// Helper: ASN.1 OID
fn oid(components: &[u64]) -> Vec<u8> {
    let mut packed: Vec<u8> = vec![];
    packed.push((components[0] * 40 + components[1]) as u8);
    for &comp in &components[2..] {
        let mut n = comp;
        let mut bytes = vec![];
        loop {
            bytes.insert(0, (n & 0x7F) as u8);
            n >>= 7;
            if n == 0 {
                break;
            }
        }
        if let Some(b) = bytes.get_mut(0) {
            *b |= 0x80;
        }
        packed.extend(bytes);
    }
    tag(0x06, &packed)
}

/// Helper: ASN.1 UTF8String
fn utf8_string(s: &str) -> Vec<u8> {
    tag(0x0C, s.as_bytes())
}

/// Helper: ASN.1 Bit String (unused bits = 0)
fn bit_string(data: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00];
    content.extend_from_slice(data);
    tag(0x03, &content)
}

/// Helper: ASN.1 Sequence
fn sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = elements.iter().flatten().cloned().collect();
    tag(0x30, &body)
}

/// Helper: ASN.1 SET
fn set(elements: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = elements.iter().flatten().cloned().collect();
    tag(0x31, &body)
}

/// Helper: GeneralizedTime (YYMMDDHHMMSSZ)
fn generalized_time(dt: DateTime<Utc>) -> Vec<u8> {
    let s = dt.format("%y%m%d%H%M%SZ").to_string();
    tag(0x18, s.as_bytes())
}

#[cfg(test)]
mod tests {
    #[test]
    fn verify_self_signed_rsa() {
        let cert = super::Certificate::new_self_signed(false, "cn=WebRTC-RSA").unwrap();

        // TODO: Verify subject and issuer are the same
        // TODO: Verify subject common name is cn=WebRTC-RSA
        // TODO: Verify issuer common name is cn=WebRTC-RSA
    }

    #[test]
    fn verify_self_signed_ec_dsa() {
        let cert = super::Certificate::new_self_signed(true, "cn=ecDsa").unwrap();

        // TODO: Verify subject and issuer are the same
        // TODO: Verify subject common name is cn=ecDsa
        // TODO: Verify issuer common name is cn=ecDsa
    }

    #[test]
    fn verify_fingerprint_rsa() {
        let cert = super::Certificate::new_self_signed(false, "cn=WebRTC").unwrap();
        let fingerprint = cert.sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);
    }

    #[test]
    fn verify_fingerprint_ec_dsa() {
        let cert = super::Certificate::new_self_signed(true, "cn=WebRTC").unwrap();
        let fingerprint = cert.sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);
    }
}
