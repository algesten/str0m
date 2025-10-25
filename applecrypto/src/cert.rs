use super::AppleCryptoError;
use crate::apple_common_crypto::{CC_SHA256, CC_SHA256_DIGEST_LENGTH};
use security_framework::certificate::SecCertificate;
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey};
use std::ffi::c_void;
use std::time::SystemTime;

#[derive(Debug)]
pub struct Certificate {
    certificate: SecCertificate,
}

impl Certificate {
    pub fn new_self_signed(use_ec_dsa_keys: bool, subject: &str) -> Result<Self, AppleCryptoError> {
        // OIDs
        let common_name = oid(&[2, 5, 4, 3]);
        let basic_constraints = oid(&[2, 5, 29, 19]);

        // Choose algorithm-specific OIDs and parameters
        let (key_alg_oid, sig_alg_oid, key_type, key_size, sign_algorithm) = if use_ec_dsa_keys {
            (
                oid(&[1, 2, 840, 10045, 2, 1]),    // ecPublicKey
                oid(&[1, 2, 840, 10045, 4, 3, 2]), // ecdsa-with-SHA256
                KeyType::ec(),
                256,
                Algorithm::ECDSASignatureDigestX962SHA256,
            )
        } else {
            (
                oid(&[1, 2, 840, 113549, 1, 1, 1]),  // rsaEncryption
                oid(&[1, 2, 840, 113549, 1, 1, 11]), // sha256WithRSAEncryption
                KeyType::rsa(),
                2048,
                Algorithm::RSASignatureDigestPKCS1v15SHA256,
            )
        };

        // 1. Generate key pair
        let mut key_options = GenerateKeyOptions::default();
        key_options.set_key_type(key_type);
        key_options.set_size_in_bits(key_size);
        let key = SecKey::new(&key_options)?;
        let public_key = key.public_key().unwrap();

        // 2. Export public key as DER (SPKI)
        let public_key_data = public_key.external_representation().unwrap();
        let public_key_vec = public_key_data.to_vec();

        // Build SubjectPublicKeyInfo
        let spki = if use_ec_dsa_keys {
            // For ECDSA, we need to specify the curve (secp256r1/P-256)
            let secp256r1_oid = oid(&[1, 2, 840, 10045, 3, 1, 7]);
            sequence(&[
                sequence(&[key_alg_oid.clone(), secp256r1_oid]),
                bit_string(&public_key_vec),
            ])
        } else {
            // For RSA, AlgorithmIdentifier has NULL parameter
            sequence(&[
                sequence(&[key_alg_oid.clone(), tag(0x05, &[])]),
                bit_string(&public_key_vec),
            ])
        };

        // 3. Build TBSCertificate
        let serial = integer(1);
        let sig_alg = if use_ec_dsa_keys {
            // ECDSA signature algorithm has no parameters
            sequence(&[sig_alg_oid.clone()])
        } else {
            // RSA signature algorithm has NULL parameter
            sequence(&[sig_alg_oid.clone(), tag(0x05, &[])])
        };

        let issuer = sequence(&[set(&[sequence(&[
            common_name.clone(),
            utf8_string(subject),
        ])])]);
        let subject = issuer.clone();

        let now = SystemTime::now();
        let not_before = generalized_time(now);
        // Add 365 days (in seconds)
        let not_after = generalized_time(now + std::time::Duration::from_secs(365 * 24 * 60 * 60));

        let validity = sequence(&[not_before, not_after]);

        // basicConstraints: critical, CA:TRUE
        // The extension value is a SEQUENCE containing BOOLEAN TRUE
        let bc_value_inner = vec![0x01, 0x01, 0xFF]; // BOOLEAN TRUE (tag 0x01, length 0x01, value 0xFF)
        let bc_value = tag(0x30, &bc_value_inner); // SEQUENCE wrapping the BOOLEAN
        let bc_ext = sequence(&[
            basic_constraints,
            vec![0x01, 0x01, 0xFF], // critical = TRUE
            octet_string(&bc_value),
        ]);
        let extensions_seq = sequence(&[bc_ext]);
        let extensions = tag(0xA3, &extensions_seq); // [3] EXPLICIT

        let tbs = sequence(&[
            tag(0xA0, &integer(2)), // version v3 [0] EXPLICIT
            serial,
            sig_alg.clone(),
            issuer,
            validity,
            subject,
            spki,
            extensions,
        ]);

        // 4. SHA-256 hash of TBSCertificate
        let mut hash = [0u8; CC_SHA256_DIGEST_LENGTH];
        unsafe {
            CC_SHA256(
                tbs.as_ptr() as *const c_void,
                tbs.len() as u32,
                hash.as_mut_ptr(),
            )
        };

        // 5. Sign the hash with private key
        // Both RSASignatureDigestPKCS1v15SHA256 and ECDSASignatureDigestX962SHA256 expect pre-hashed data
        let signature = key.create_signature(sign_algorithm, &hash)?;

        // 6. Full Certificate
        let cert_der = sequence(&[tbs, sig_alg, bit_string(&signature)]);

        // 7. Create SecCertificate
        let certificate = SecCertificate::from_der(&cert_der).unwrap();

        Ok(Self { certificate })
    }

    pub fn sha256_fingerprint(&self) -> Result<[u8; 32], AppleCryptoError> {
        let der = self.certificate.to_der();
        let mut hash = [0u8; CC_SHA256_DIGEST_LENGTH];
        unsafe {
            CC_SHA256(
                der.as_ptr() as *const c_void,
                der.len() as u32,
                hash.as_mut_ptr(),
            )
        };
        Ok(hash)
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
        // Set high bit on all but the last byte
        for i in 0..bytes.len() - 1 {
            bytes[i] |= 0x80;
        }
        packed.extend(bytes);
    }
    tag(0x06, &packed)
}

/// Helper: ASN.1 UTF8String
fn utf8_string(s: &str) -> Vec<u8> {
    tag(0x0C, s.as_bytes())
}

/// Helper: ASN.1 Octet String
fn octet_string(data: &[u8]) -> Vec<u8> {
    tag(0x04, data)
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

/// Helper: GeneralizedTime (YYYYMMDDHHMMSSZ)
fn generalized_time(time: SystemTime) -> Vec<u8> {
    // Convert SystemTime to seconds since UNIX_EPOCH
    let duration = time
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards");
    let secs = duration.as_secs();

    // Convert to broken-down time (year, month, day, hour, minute, second)
    // Algorithm based on civil_from_days from Howard Hinnant's date library
    const SECONDS_PER_DAY: u64 = 86400;
    let days = (secs / SECONDS_PER_DAY) as i64;
    let time_of_day = secs % SECONDS_PER_DAY;

    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Calculate civil date from days since Unix epoch (1970-01-01)
    let z = days + 719468; // Days from 0000-03-01 to Unix epoch
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32; // Day of era
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // Year of era
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // Day of year
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let month = m;
    let day = d;

    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        year, month, day, hour, minute, second
    );
    tag(0x18, s.as_bytes())
}

#[cfg(test)]
mod tests {
    use crate::AppleCryptoError;
    use security_framework::certificate::SecCertificate;

    #[test]
    fn verify_self_signed_rsa() {
        let cert = super::Certificate::new_self_signed(false, "cn=WebRTC-RSA").unwrap();

        // Verify it's self-signed
        assert!(
            is_self_signed(&cert.certificate).unwrap(),
            "Certificate should be self-signed"
        );

        // Verify subject and issuer common names
        let subject_cn = extract_common_name_from_subject(&cert.certificate).unwrap();
        let issuer_cn = extract_common_name_from_issuer(&cert.certificate).unwrap();

        assert_eq!(subject_cn, "cn=WebRTC-RSA", "Subject CN should match");
        assert_eq!(issuer_cn, "cn=WebRTC-RSA", "Issuer CN should match");
        assert_eq!(
            subject_cn, issuer_cn,
            "Subject and issuer CN should be the same"
        );
    }

    #[test]
    fn verify_self_signed_ec_dsa() {
        let cert = super::Certificate::new_self_signed(true, "cn=ecDsa").unwrap();

        // Verify it's self-signed
        assert!(
            is_self_signed(&cert.certificate).unwrap(),
            "Certificate should be self-signed"
        );

        // Verify subject and issuer common names
        let subject_cn = extract_common_name_from_subject(&cert.certificate).unwrap();
        let issuer_cn = extract_common_name_from_issuer(&cert.certificate).unwrap();

        assert_eq!(subject_cn, "cn=ecDsa", "Subject CN should match");
        assert_eq!(issuer_cn, "cn=ecDsa", "Issuer CN should match");
        assert_eq!(
            subject_cn, issuer_cn,
            "Subject and issuer CN should be the same"
        );
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

    /// Check if this is a self-signed certificate (issuer == subject)
    fn is_self_signed(certificate: &SecCertificate) -> Result<bool, AppleCryptoError> {
        let der = certificate.to_der();
        let (issuer, subject) = parse_issuer_and_subject(&der)?;
        Ok(issuer == subject)
    }

    /// Extract common name from subject
    fn extract_common_name_from_subject(
        certificate: &SecCertificate,
    ) -> Result<String, AppleCryptoError> {
        let der = certificate.to_der();
        let (_, subject) = parse_issuer_and_subject(&der)?;
        extract_cn_from_name(&subject)
    }

    /// Extract common name from issuer
    fn extract_common_name_from_issuer(
        certificate: &SecCertificate,
    ) -> Result<String, AppleCryptoError> {
        let der = certificate.to_der();
        let (issuer, _) = parse_issuer_and_subject(&der)?;
        extract_cn_from_name(&issuer)
    }

    /// Parse issuer and subject from certificate DER
    fn parse_issuer_and_subject(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AppleCryptoError> {
        // Certificate structure:
        // SEQUENCE {
        //   tbsCertificate SEQUENCE {
        //     [0] version
        //     serialNumber
        //     signature AlgorithmIdentifier
        //     issuer Name              <- we want this
        //     validity
        //     subject Name             <- and this
        //     ...
        //   }
        // }

        let mut pos = 0;

        // Skip outer SEQUENCE tag and length
        if der[pos] != 0x30 {
            return Err(AppleCryptoError::Generic(
                "Invalid certificate format".to_string(),
            ));
        }
        pos += 1;
        pos += skip_length(&der[pos..])?;

        // Skip TBS SEQUENCE tag and length
        if der[pos] != 0x30 {
            return Err(AppleCryptoError::Generic(
                "Invalid TBS certificate format".to_string(),
            ));
        }
        pos += 1;
        pos += skip_length(&der[pos..])?;

        // Skip version [0] EXPLICIT
        if der[pos] == 0xA0 {
            pos += 1;
            let len = read_length(&der[pos..])?;
            pos += skip_length(&der[pos..])?;
            pos += len;
        }

        // Skip serial number
        pos += skip_asn1_element(&der[pos..])?;

        // Skip signature algorithm
        pos += skip_asn1_element(&der[pos..])?;

        // Read issuer
        let issuer_start = pos;
        let issuer_len = skip_asn1_element(&der[pos..])?;
        let issuer = der[issuer_start..issuer_start + issuer_len].to_vec();
        pos += issuer_len;

        // Skip validity
        pos += skip_asn1_element(&der[pos..])?;

        // Read subject
        let subject_start = pos;
        let subject_len = skip_asn1_element(&der[pos..])?;
        let subject = der[subject_start..subject_start + subject_len].to_vec();

        Ok((issuer, subject))
    }

    /// Extract CN from a Name structure
    fn extract_cn_from_name(name: &[u8]) -> Result<String, AppleCryptoError> {
        // Name is a SEQUENCE of SETs of AttributeTypeAndValue
        // We're looking for the one with OID 2.5.4.3 (commonName)
        let cn_oid = vec![0x06, 0x03, 0x55, 0x04, 0x03]; // OID encoding for 2.5.4.3

        let mut pos = 0;

        // Skip SEQUENCE tag and length
        if name[pos] != 0x30 {
            return Err(AppleCryptoError::Generic("Invalid Name format".to_string()));
        }
        pos += 1;
        pos += skip_length(&name[pos..])?;

        // Iterate through SETs
        while pos < name.len() {
            if name[pos] != 0x31 {
                // SET tag
                break;
            }
            pos += 1;
            let set_len = read_length(&name[pos..])?;
            pos += skip_length(&name[pos..])?;
            let set_end = pos + set_len;

            // Check if this SET contains the CN OID
            if pos + cn_oid.len() < name.len()
                && &name[pos + 2..pos + 2 + cn_oid.len()] == &cn_oid[..]
            {
                // Found CN! Skip SEQUENCE and OID
                pos += 2; // SEQUENCE tag and length
                pos += cn_oid.len();

                // Read the string value (usually UTF8String tag 0x0C)
                let string_tag = name[pos];
                pos += 1;
                let string_len = read_length(&name[pos..])?;
                pos += skip_length(&name[pos..])?;

                if string_tag == 0x0C || string_tag == 0x13 {
                    // UTF8String or PrintableString
                    let cn_bytes = &name[pos..pos + string_len];
                    return String::from_utf8(cn_bytes.to_vec())
                        .map_err(|_| AppleCryptoError::Generic("Invalid UTF-8 in CN".to_string()));
                }
            }

            pos = set_end;
        }

        Err(AppleCryptoError::Generic(
            "CN not found in Name".to_string(),
        ))
    }

    /// Read ASN.1 length field and return the length value
    fn read_length(data: &[u8]) -> Result<usize, AppleCryptoError> {
        if data[0] < 0x80 {
            Ok(data[0] as usize)
        } else {
            let num_bytes = (data[0] & 0x7F) as usize;
            let mut len = 0;
            for i in 0..num_bytes {
                len = (len << 8) | data[1 + i] as usize;
            }
            Ok(len)
        }
    }

    /// Skip ASN.1 length field and return how many bytes were skipped
    fn skip_length(data: &[u8]) -> Result<usize, AppleCryptoError> {
        if data[0] < 0x80 {
            Ok(1)
        } else {
            Ok(1 + (data[0] & 0x7F) as usize)
        }
    }

    /// Skip an entire ASN.1 element (tag + length + value) and return total size
    fn skip_asn1_element(data: &[u8]) -> Result<usize, AppleCryptoError> {
        let mut pos = 1; // Skip tag
        let len = read_length(&data[pos..])?;
        pos += skip_length(&data[pos..])?;
        Ok(pos + len)
    }
}
