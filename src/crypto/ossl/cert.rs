use std::time::SystemTime;

use openssl::asn1::{Asn1Integer, Asn1Time, Asn1Type};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Name, X509};

use crate::crypto::dtls::DTLS_CERT_IDENTITY;
use crate::crypto::Fingerprint;

use super::CryptoError;
use super::OsslDtlsImpl;

const RSA_F4: u32 = 0x10001;

/// Certificate used for DTLS.
#[derive(Debug, Clone)]
pub struct OsslDtlsCert {
    pub(crate) pkey: PKey<Private>,
    pub(crate) x509: X509,
}

impl OsslDtlsCert {
    /// Creates a new (self signed) DTLS certificate.
    pub fn new() -> Self {
        Self::self_signed().expect("create dtls cert")
    }

    // The libWebRTC code we try to match is at:
    // https://webrtc.googlesource.com/src/+/1568f1b1330f94494197696fe235094e6293b258/rtc_base/openssl_certificate.cc#58
    fn self_signed() -> Result<Self, CryptoError> {
        let f4 = BigNum::from_u32(RSA_F4).unwrap();
        let key = Rsa::generate_with_e(2048, &f4)?;
        let pkey = PKey::from_rsa(key)?;

        let mut x509b = X509::builder()?;
        x509b.set_version(2)?; // X509.V3 (zero indexed)

        // For Firefox, the serial number must be unique across all certificates, including those of other
        // processes/machines! See https://github.com/versatica/mediasoup/issues/127#issuecomment-474460153
        // and https://github.com/algesten/str0m/issues/517
        let mut serial_buf = [0u8; 16];
        openssl::rand::rand_bytes(&mut serial_buf)?;

        let serial_bn = BigNum::from_slice(&serial_buf)?;
        let serial = Asn1Integer::from_bn(&serial_bn)?;
        x509b.set_serial_number(&serial)?;
        let before = Asn1Time::from_unix(unix_time() - 3600)?;
        x509b.set_not_before(&before)?;
        let after = Asn1Time::days_from_now(7)?;
        x509b.set_not_after(&after)?;
        x509b.set_pubkey(&pkey)?;

        // The libWebRTC code for this is:
        //
        // !X509_NAME_add_entry_by_NID(name.get(), NID_commonName, MBSTRING_UTF8,
        // (unsigned char*)params.common_name.c_str(), -1, -1, 0) ||
        //
        // libWebRTC allows this name to be configured by the user of the library.
        // That's a future TODO for str0m.
        let mut nameb = X509Name::builder()?;
        nameb.append_entry_by_nid_with_type(
            Nid::COMMONNAME,
            DTLS_CERT_IDENTITY,
            Asn1Type::UTF8STRING,
        )?;

        let name = nameb.build();

        x509b.set_subject_name(&name)?;
        x509b.set_issuer_name(&name)?;

        x509b.sign(&pkey, MessageDigest::sha1())?;
        let x509 = x509b.build();

        Ok(OsslDtlsCert { pkey, x509 })
    }

    /// Produce a (public) fingerprint of the cert.
    ///
    /// This is sent via SDP to the other peer to lock down the DTLS
    /// to this specific certificate.
    pub fn fingerprint(&self) -> Fingerprint {
        let digest: &[u8] = &self
            .x509
            .digest(MessageDigest::sha256())
            .expect("digest to fingerprint");

        Fingerprint {
            hash_func: "sha-256".into(),
            bytes: digest.to_vec(),
        }
    }

    pub(crate) fn new_dtls_impl(&self) -> Result<OsslDtlsImpl, CryptoError> {
        OsslDtlsImpl::new(self.clone())
    }
}

// TODO: Refactor away this use of System::now, to instead go via InstantExt
// and base the time on the first Instant. This would require lazy init of
// Dtls, or that we pass a first ever Instant into the creation of Rtc.
//
// This is not a super high priority since it's only used for setting a before
// time in the generated certificate, and one hour back from that.
pub fn unix_time() -> libc::time_t {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as libc::time_t
}
