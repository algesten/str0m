//! DTLS implementation using dimpl with Windows CNG as crypto backend.

use std::sync::Arc;
use std::time::Instant;

use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::DtlsVersion;
use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};
use time::{Date, OffsetDateTime, PrimitiveDateTime};

use dimpl::{Config, Dtls, DtlsCertificate};

use windows::Win32::Security::Cryptography::{BCRYPT_SHA256_ALG_HANDLE, BCryptHash};

use crate::WinCryptoError;

// ============================================================================
// Certificate Generation
// ============================================================================

fn generate_certificate_impl() -> Result<DtlsCert, CryptoError> {
    let now = OffsetDateTime::now_utc();

    // Generate ECDSA P-256 key pair using Windows CNG
    let (key_handle, x, y, d) = crate::dimpl_provider::sign::generate_ecdsa_p256_keypair()
        .map_err(|e| CryptoError::Other(format!("Key generation failed: {e}")))?;

    // Build the uncompressed public key: 04 || X || Y
    let mut public_key_bytes = Vec::with_capacity(65);
    public_key_bytes.push(0x04);
    public_key_bytes.extend_from_slice(&x);
    public_key_bytes.extend_from_slice(&y);

    // Build self-signed X.509 certificate
    let certificate = build_self_signed_cert(&public_key_bytes, *key_handle, now)?;

    // Wrap private key as PKCS#8 DER
    let private_key_der = wrap_ec_private_key_pkcs8(&d, &public_key_bytes)?;

    Ok(DtlsCert {
        certificate,
        private_key: private_key_der,
    })
}

/// Build a minimal self-signed X.509 v3 certificate.
fn build_self_signed_cert(
    public_key_bytes: &[u8],
    signing_key: windows::Win32::Security::Cryptography::BCRYPT_KEY_HANDLE,
    now: OffsetDateTime,
) -> Result<Vec<u8>, CryptoError> {
    let tbs = build_tbs_certificate(public_key_bytes, now)?;

    // Hash the TBS certificate with SHA-256
    let mut hash = [0u8; 32];
    // SAFETY: Microsoft Learn documents `BCryptHash` as borrowing the input
    // and output buffers only for the duration of the call; both outlive this
    // block.
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcrypthash
    unsafe {
        WinCryptoError::from_ntstatus(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, &tbs, &mut hash))
            .map_err(|e| CryptoError::Other(format!("SHA-256 hash failed: {e}")))?;
    }

    // Sign the hash with ECDSA
    let raw_sig = crate::dimpl_provider::sign::ecdsa_sign_hash(signing_key, &hash)
        .map_err(|e| CryptoError::Other(format!("Signing failed: {e}")))?;

    // Convert raw (r,s) to DER-encoded signature.
    let der_sig = crate::dimpl_provider::sign::raw_rs_to_der(&raw_sig)
        .map_err(|e| CryptoError::Other(format!("DER encoding failed: {e}")))?;

    // Encode the full certificate
    let ecdsa_with_sha256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    let sig_algorithm = encode_algorithm_identifier(ecdsa_with_sha256_oid);
    let signature_bits = encode_bit_string(&der_sig);

    let mut cert_content = Vec::new();
    cert_content.extend_from_slice(&tbs);
    cert_content.extend_from_slice(&sig_algorithm);
    cert_content.extend_from_slice(&signature_bits);

    Ok(encode_sequence(&cert_content))
}

fn build_tbs_certificate(
    public_key_bytes: &[u8],
    now: OffsetDateTime,
) -> Result<Vec<u8>, CryptoError> {
    let mut tbs = Vec::new();

    // Version: v3
    let version = encode_explicit_tag(0, &encode_integer(&[2]));
    tbs.extend_from_slice(&version);

    // Serial number (random)
    let mut serial = [0u8; 16];
    use windows::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG;
    use windows::Win32::Security::Cryptography::BCryptGenRandom;
    // SAFETY: Microsoft Learn documents `BCryptGenRandom` as filling the
    // caller-provided mutable buffer for the duration of the call; `serial`
    // outlives this block.
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
    unsafe {
        WinCryptoError::from_ntstatus(BCryptGenRandom(
            None,
            &mut serial,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        ))
        .map_err(|e| CryptoError::Other(format!("Random failed: {e}")))?;
    }
    serial[0] &= 0x7F; // Ensure positive
    tbs.extend_from_slice(&encode_integer(&serial));

    // Signature algorithm: ecdsa-with-SHA256
    let ecdsa_with_sha256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    tbs.extend_from_slice(&encode_algorithm_identifier(ecdsa_with_sha256_oid));

    // Issuer: CN=WebRTC
    let issuer = encode_name("WebRTC");
    tbs.extend_from_slice(&issuer);

    tbs.extend_from_slice(&encode_validity(now)?);

    // Subject: CN=WebRTC
    tbs.extend_from_slice(&issuer);

    // Subject Public Key Info
    let spki = encode_ec_public_key_info(public_key_bytes);
    tbs.extend_from_slice(&spki);

    Ok(encode_sequence(&tbs))
}

// ============================================================================
// ASN.1 DER Encoding Helpers
// ============================================================================

fn encode_sequence(content: &[u8]) -> Vec<u8> {
    encode_tag(0x30, content)
}

fn encode_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    encode_length(content.len(), &mut result);
    result.extend_from_slice(content);
    result
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

fn encode_integer(value: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0 {
        start += 1;
    }
    let value = &value[start..];

    if value[0] & 0x80 != 0 {
        let mut content = vec![0x00];
        content.extend_from_slice(value);
        encode_tag(0x02, &content)
    } else {
        encode_tag(0x02, value)
    }
}

fn encode_explicit_tag(tag_num: u8, content: &[u8]) -> Vec<u8> {
    encode_tag(0xA0 | tag_num, content)
}

fn encode_oid(oid_bytes: &[u8]) -> Vec<u8> {
    encode_tag(0x06, oid_bytes)
}

fn encode_validity(now: OffsetDateTime) -> Result<Vec<u8>, CryptoError> {
    let not_before = encode_x509_time(now);
    let not_after = encode_x509_time(add_one_year(now)?);

    Ok(encode_sequence(&[not_before, not_after].concat()))
}

fn encode_x509_time(time: OffsetDateTime) -> Vec<u8> {
    let year = time.year();
    let month = time.month() as u8;
    let day = time.day();
    let hour = time.hour();
    let minute = time.minute();
    let second = time.second();

    let encoded = if (1950..2050).contains(&year) {
        format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            year.rem_euclid(100),
            month,
            day,
            hour,
            minute,
            second
        )
    } else {
        format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            year, month, day, hour, minute, second
        )
    };

    let tag = if (1950..2050).contains(&year) {
        0x17
    } else {
        0x18
    };

    encode_tag(tag, encoded.as_bytes())
}

fn add_one_year(time: OffsetDateTime) -> Result<OffsetDateTime, CryptoError> {
    let target_year = time
        .year()
        .checked_add(1)
        .ok_or_else(|| CryptoError::Other("Certificate validity year overflow".to_string()))?;

    let month = time.month();
    let mut day = time.day();

    loop {
        match Date::from_calendar_date(target_year, month, day) {
            Ok(date) => {
                let next = PrimitiveDateTime::new(date, time.time()).assume_utc();
                return Ok(next);
            }
            Err(_) if day > 28 => day -= 1,
            Err(e) => {
                return Err(CryptoError::Other(format!(
                    "Invalid certificate not_after date: {e}"
                )));
            }
        }
    }
}

fn encode_algorithm_identifier(oid_bytes: &[u8]) -> Vec<u8> {
    let oid = encode_oid(oid_bytes);
    encode_sequence(&oid)
}

fn encode_name(cn: &str) -> Vec<u8> {
    let cn_oid = &[0x55, 0x04, 0x03];
    let oid = encode_oid(cn_oid);
    let value = encode_tag(0x0C, cn.as_bytes());
    let attr_type_value = encode_sequence(&[oid, value].concat());
    let rdn = encode_tag(0x31, &attr_type_value);
    encode_sequence(&rdn)
}

fn encode_ec_public_key_info(public_key_bytes: &[u8]) -> Vec<u8> {
    let ec_public_key_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let prime256v1_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let algorithm =
        encode_sequence(&[encode_oid(ec_public_key_oid), encode_oid(prime256v1_oid)].concat());
    let public_key_bits = encode_bit_string(public_key_bytes);
    encode_sequence(&[algorithm, public_key_bits].concat())
}

fn encode_bit_string(data: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00];
    content.extend_from_slice(data);
    encode_tag(0x03, &content)
}

fn wrap_ec_private_key_pkcs8(
    private_scalar: &[u8],
    public_key_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Version: 0
    let version = encode_integer(&[0]);

    // Algorithm: ecPublicKey with prime256v1
    let ec_public_key_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let prime256v1_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let algorithm =
        encode_sequence(&[encode_oid(ec_public_key_oid), encode_oid(prime256v1_oid)].concat());

    // PrivateKey: SEC1 ECPrivateKey wrapped in OCTET STRING
    let ec_private_key = encode_ec_private_key(private_scalar, public_key_bytes);
    let private_key = encode_tag(0x04, &ec_private_key);

    Ok(encode_sequence(&[version, algorithm, private_key].concat()))
}

fn encode_ec_private_key(private_scalar: &[u8], public_key_bytes: &[u8]) -> Vec<u8> {
    let version = encode_integer(&[1]);
    let private_key = encode_tag(0x04, private_scalar);

    let prime256v1_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let params = encode_explicit_tag(0, &encode_oid(prime256v1_oid));

    let public_key_bits = encode_bit_string(public_key_bytes);
    let public_key = encode_explicit_tag(1, &public_key_bits);

    encode_sequence(&[version, private_key, params, public_key].concat())
}

// ============================================================================
// DTLS Provider Implementation
// ============================================================================

#[derive(Debug)]
pub(crate) struct WinCryptoDtlsProvider;

impl DtlsProvider for WinCryptoDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        generate_certificate_impl().ok()
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let dimpl_cert = DtlsCertificate {
            certificate: cert.certificate.clone(),
            private_key: cert.private_key.clone(),
        };

        let mut builder = Config::builder();
        if self.is_test() {
            builder = builder.dangerously_set_rng_seed(42);
        }

        let config = builder
            .with_crypto_provider(crate::dimpl_provider::default_provider())
            .build()
            .map_err(|e| CryptoError::Other(format!("dimpl config creation failed: {e}")))?;

        let config = Arc::new(config);
        let dtls = match dtls_version {
            DtlsVersion::Dtls12 => Dtls::new_12(config, dimpl_cert, now),
            DtlsVersion::Dtls13 => Dtls::new_13(config, dimpl_cert, now),
            DtlsVersion::Auto => Dtls::new_auto(config, dimpl_cert, now),
            _ => {
                return Err(CryptoError::Other(format!(
                    "Unsupported DTLS version: {dtls_version}"
                )));
            }
        };

        Ok(Box::new(WinCryptoDtlsInstance { dtls }))
    }
}

// ============================================================================
// DTLS Instance Wrapper
// ============================================================================

struct WinCryptoDtlsInstance {
    dtls: Dtls,
}

impl std::fmt::Debug for WinCryptoDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinCryptoDtlsInstance").finish()
    }
}

impl DtlsInstance for WinCryptoDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.dtls.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        self.dtls.poll_output(buf)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.dtls.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.dtls.is_active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Month, Time};

    fn utc_datetime(
        year: i32,
        month: Month,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> OffsetDateTime {
        PrimitiveDateTime::new(
            Date::from_calendar_date(year, month, day).unwrap(),
            Time::from_hms(hour, minute, second).unwrap(),
        )
        .assume_utc()
    }

    #[test]
    fn x509_time_uses_utc_time_through_2049() {
        let encoded = encode_x509_time(utc_datetime(2049, Month::December, 31, 23, 59, 59));

        assert_eq!(encoded, b"\x17\r491231235959Z");
    }

    #[test]
    fn x509_time_uses_generalized_time_from_2050() {
        let encoded = encode_x509_time(utc_datetime(2050, Month::January, 1, 0, 0, 0));

        assert_eq!(encoded, b"\x18\x0f20500101000000Z");
    }

    #[test]
    fn add_one_year_clamps_leap_day() {
        let next = add_one_year(utc_datetime(2024, Month::February, 29, 12, 34, 56)).unwrap();

        assert_eq!(next, utc_datetime(2025, Month::February, 28, 12, 34, 56));
    }
}
