//! Common dimpl crypto provider helpers.
//!
//! Provides [`DimplCommonHmacProvider`] and the [`impl_hmac_providers!`] macro
//! so that a single HMAC implementation automatically yields `HmacProvider`,
//! `PrfProvider`, and `HkdfProvider`.
//!
//! Also provides [`DimplCryptoDtlsInstance`] for wrapping a dimpl DTLS session,
//! and helpers for building self-signed X.509 certificates and PKCS#8 keys.

use std::{sync::Arc, time::Instant};

use dimpl::HashAlgorithm;

use super::dtls::DtlsInstance;
use super::{CryptoError, DtlsVersion};

/// Re-exports consumed by the [`impl_hmac_providers!`] macro.
///
/// Not part of the public API.
#[doc(hidden)]
#[allow(unused_imports)]
pub mod _reexport {
    pub use dimpl::HashAlgorithm;
    pub use dimpl::crypto::{Buf, HkdfProvider, HmacProvider, PrfProvider};
}

/// Implement this trait with a single HMAC function, then invoke
/// `impl_hmac_providers!(YourType)` to get `HmacProvider`, `PrfProvider`,
/// and `HkdfProvider` implementations for free.
pub trait DimplCommonHmacProvider {
    /// Compute HMAC for the given hash algorithm, writing the result to `out`.
    /// Returns the number of bytes written.
    fn hmac(
        &self,
        hash: HashAlgorithm,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, String>;
}

/// Generates `HmacProvider`, `PrfProvider`, and `HkdfProvider` implementations
/// for a type that implements [`DimplCommonHmacProvider`].
#[macro_export]
macro_rules! impl_hmac_providers {
    ($ty:ty) => {
        impl $crate::crypto::dimpl::_reexport::HmacProvider for $ty {
            fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
                use $crate::crypto::dimpl::DimplCommonHmacProvider as _;
                let mut out = [0u8; 32];
                self.hmac(
                    $crate::crypto::dimpl::_reexport::HashAlgorithm::SHA256,
                    key,
                    data,
                    &mut out,
                )?;
                Ok(out)
            }
        }

        impl $crate::crypto::dimpl::_reexport::PrfProvider for $ty {
            fn prf_tls12(
                &self,
                secret: &[u8],
                label: &str,
                seed: &[u8],
                out: &mut $crate::crypto::dimpl::_reexport::Buf,
                output_len: usize,
                scratch: &mut $crate::crypto::dimpl::_reexport::Buf,
                hash: $crate::crypto::dimpl::_reexport::HashAlgorithm,
            ) -> Result<(), String> {
                use $crate::crypto::dimpl::DimplCommonHmacProvider as _;
                const MAX: usize = 48; // HMAC-SHA384 output size

                let mut hmac_a = [0u8; MAX];

                scratch.clear();
                scratch.extend_from_slice(label.as_bytes());
                scratch.extend_from_slice(seed);
                let label_seed = scratch.as_ref();

                let hash_len = self.hmac(hash, secret, label_seed, hmac_a.as_mut_slice())?;

                scratch.clear();
                scratch.extend_from_slice(&hmac_a[..hash_len]);
                scratch.extend_from_slice(label.as_bytes());
                scratch.extend_from_slice(seed);
                let payload = scratch.as_mut();

                out.clear();
                while out.len() < output_len {
                    let mut hmac_block = [0u8; MAX];
                    let hmac_block_length =
                        self.hmac(hash, secret, payload, hmac_block.as_mut_slice())?;

                    let remaining = output_len - out.len();
                    let to_copy = std::cmp::min(remaining, hmac_block_length);
                    out.extend_from_slice(&hmac_block[..to_copy]);

                    if out.len() < output_len {
                        self.hmac(hash, secret, &payload[..hash_len], hmac_a.as_mut_slice())?;
                        payload[..hash_len].copy_from_slice(&hmac_a[..hash_len]);
                    }
                }
                Ok(())
            }
        }

        impl $crate::crypto::dimpl::_reexport::HkdfProvider for $ty {
            fn hkdf_extract(
                &self,
                hash: $crate::crypto::dimpl::_reexport::HashAlgorithm,
                salt: &[u8],
                ikm: &[u8],
                out: &mut $crate::crypto::dimpl::_reexport::Buf,
            ) -> Result<(), String> {
                use $crate::crypto::dimpl::DimplCommonHmacProvider as _;
                const MAX: usize = 48;

                out.clear();
                let hash_len = hash.output_len();
                let zero_salt: Vec<u8>;
                let actual_salt = if salt.is_empty() {
                    zero_salt = vec![0u8; hash_len];
                    &zero_salt[..]
                } else {
                    salt
                };
                let mut prk_out = [0u8; MAX];
                let prk_len = self.hmac(hash, actual_salt, ikm, &mut prk_out)?;
                out.extend_from_slice(&prk_out[..prk_len]);
                Ok(())
            }

            fn hkdf_expand(
                &self,
                hash: $crate::crypto::dimpl::_reexport::HashAlgorithm,
                prk: &[u8],
                info: &[u8],
                out: &mut $crate::crypto::dimpl::_reexport::Buf,
                output_len: usize,
            ) -> Result<(), String> {
                use $crate::crypto::dimpl::DimplCommonHmacProvider as _;
                const MAX: usize = 48;

                let hash_len = hash.output_len();
                let n = output_len.div_ceil(hash_len);
                if n > 255 {
                    return Err("HKDF output too long".into());
                }

                let mut t_prev = [0u8; MAX];
                let mut t_prev_len = 0usize;

                out.clear();
                for i in 1..=n {
                    let mut input = Vec::with_capacity(t_prev_len + info.len() + 1);
                    input.extend_from_slice(&t_prev[..t_prev_len]);
                    input.extend_from_slice(info);
                    input.push(i as u8);

                    t_prev_len = self.hmac(hash, prk, &input, &mut t_prev)?;

                    let remaining = output_len - out.len();
                    let to_copy = std::cmp::min(remaining, t_prev_len);
                    out.extend_from_slice(&t_prev[..to_copy]);
                }

                Ok(())
            }

            fn hkdf_expand_label(
                &self,
                hash: $crate::crypto::dimpl::_reexport::HashAlgorithm,
                secret: &[u8],
                label: &[u8],
                context: &[u8],
                out: &mut $crate::crypto::dimpl::_reexport::Buf,
                output_len: usize,
            ) -> Result<(), String> {
                let info =
                    $crate::crypto::dimpl::build_hkdf_label(b"tls13 ", label, context, output_len)?;
                self.hkdf_expand(hash, secret, &info, out, output_len)
            }

            fn hkdf_expand_label_dtls13(
                &self,
                hash: $crate::crypto::dimpl::_reexport::HashAlgorithm,
                secret: &[u8],
                label: &[u8],
                context: &[u8],
                out: &mut $crate::crypto::dimpl::_reexport::Buf,
                output_len: usize,
            ) -> Result<(), String> {
                let info =
                    $crate::crypto::dimpl::build_hkdf_label(b"dtls13", label, context, output_len)?;
                self.hkdf_expand(hash, secret, &info, out, output_len)
            }
        }

        #[cfg(test)]
        mod dimpl_common_hmac_tests {
            use super::*;
            use $crate::crypto::dimpl::_reexport::{
                Buf, HashAlgorithm, HkdfProvider, HmacProvider, PrfProvider,
            };

            fn hex_to_vec(hex: &str) -> Vec<u8> {
                let hex = hex.replace(" ", "").replace("\n", "");
                let mut v = Vec::new();
                for i in 0..hex.len() / 2 {
                    let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
                    v.push(byte);
                }
                v
            }

            fn slice_to_hex(data: &[u8]) -> String {
                let mut s = String::new();
                for byte in data.iter() {
                    s.push_str(&format!("{:02x}", byte));
                }
                s
            }

            /// Convert an ASCII hex array into a byte array at compile time.
            macro_rules! hex_as_bytes {
                ($input:expr) => {{
                    const fn from_hex_char(c: u8) -> u8 {
                        match c {
                            b'0'..=b'9' => c - b'0',
                            b'a'..=b'f' => c - b'a' + 10,
                            b'A'..=b'F' => c - b'A' + 10,
                            _ => panic!("Invalid hex character"),
                        }
                    }

                    const INPUT: &[u8] = $input;
                    const LEN: usize = INPUT.len();
                    const OUTPUT_LEN: usize = LEN / 2;

                    const fn convert() -> [u8; OUTPUT_LEN] {
                        assert!(LEN % 2 == 0, "Hex string length must be even");

                        let mut out = [0u8; OUTPUT_LEN];
                        let mut i = 0;
                        while i < LEN {
                            out[i / 2] =
                                (from_hex_char(INPUT[i]) << 4) | from_hex_char(INPUT[i + 1]);
                            i += 2;
                        }
                        out
                    }

                    convert()
                }};
            }

            fn provider() -> $ty {
                <$ty>::default()
            }

            // HMAC-SHA-256 Test Vectors from RFC 4231

            #[test]
            fn test_hmac_sha256_test_case_1() {
                let key = hex_to_vec("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let data = b"Hi There";
                let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

                let result = provider().hmac_sha256(&key, data).unwrap();
                assert_eq!(slice_to_hex(&result), expected);
            }

            #[test]
            fn test_hmac_sha256_test_case_2() {
                let key = b"Jefe";
                let data = b"what do ya want for nothing?";
                let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

                let result = provider().hmac_sha256(key, data).unwrap();
                assert_eq!(slice_to_hex(&result), expected);
            }

            #[test]
            fn test_hmac_sha256_test_case_3() {
                let key = hex_to_vec("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                let data = hex_to_vec(
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
                     dddddddddddddddddddddddddddddddddddd",
                );
                let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

                let result = provider().hmac_sha256(&key, &data).unwrap();
                assert_eq!(slice_to_hex(&result), expected);
            }

            #[test]
            fn test_hmac_sha256_test_case_4() {
                let key = hex_to_vec("0102030405060708090a0b0c0d0e0f10111213141516171819");
                let data = hex_to_vec(
                    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                     cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                );
                let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

                let result = provider().hmac_sha256(&key, &data).unwrap();
                assert_eq!(slice_to_hex(&result), expected);
            }

            #[test]
            fn test_hmac_sha256_test_case_6() {
                // Test with a key larger than block size (> 64 bytes)
                let key = vec![0xaa; 131];
                let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
                let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

                let result = provider().hmac_sha256(&key, data).unwrap();
                assert_eq!(slice_to_hex(&result), expected);
            }

            #[test]
            fn test_hmac_sha256_test_case_7() {
                // Test with a key larger than block size and large data
                let key = vec![0xaa; 131];
                let data = b"This is a test using a larger than block-size key and a larger \
                    than block-size data. The key needs to be hashed before being used \
                    by the HMAC algorithm.";
                let expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

                let result = provider().hmac_sha256(&key, data).unwrap();
                assert_eq!(slice_to_hex(&result), expected);
            }

            #[test]
            fn test_prf_tls12_sha256() {
                // Test vector from https://github.com/xomexh/TLS-PRF
                let mut output = Buf::new();
                let mut scratch = Buf::new();
                assert!(
                    provider()
                        .prf_tls12(
                            &hex_as_bytes!(b"9bbe436ba940f017b17652849a71db35"),
                            "test label",
                            &hex_as_bytes!(b"a0ba9f936cda311827a6f796ffd5198c"),
                            &mut output,
                            100,
                            &mut scratch,
                            HashAlgorithm::SHA256,
                        )
                        .is_ok()
                );
                assert_eq!(
                    output.as_ref(),
                    &hex_as_bytes!(
                        b"e3f229ba727be17b8d122620557cd453c2aab21d\
                          07c3d495329b52d4e61edb5a6b301791e90d35c9\
                          c9a46b4e14baf9af0fa022f7077def17abfd3797\
                          c0564bab4fbc91666e9def9b97fce34f796789ba\
                          a48082d122ee42c5a72e5a5110fff70187347b66"
                    )
                );
            }

            // HKDF Test Vectors from RFC 5869
            // https://tools.ietf.org/html/rfc5869

            #[test]
            fn test_hkdf_sha256_test_case_1() {
                // Test Case 1 - Basic test case with SHA-256
                let ikm = hex_to_vec("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = hex_to_vec("000102030405060708090a0b0c");
                let info = hex_to_vec("f0f1f2f3f4f5f6f7f8f9");
                let expected_prk =
                    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
                let expected_okm = "3cb25f25faacd57a90434f64d0362f2a\
                                    2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                                    34007208d5b887185865";

                let p = provider();

                let mut prk = Buf::new();
                p.hkdf_extract(HashAlgorithm::SHA256, &salt, &ikm, &mut prk)
                    .unwrap();
                assert_eq!(slice_to_hex(prk.as_ref()), expected_prk);

                let mut okm = Buf::new();
                p.hkdf_expand(HashAlgorithm::SHA256, prk.as_ref(), &info, &mut okm, 42)
                    .unwrap();
                assert_eq!(slice_to_hex(okm.as_ref()), expected_okm);
            }

            #[test]
            fn test_hkdf_sha256_test_case_2() {
                // Test Case 2 - Longer inputs/outputs with SHA-256
                let ikm = hex_to_vec(
                    "000102030405060708090a0b0c0d0e0f\
                     101112131415161718191a1b1c1d1e1f\
                     202122232425262728292a2b2c2d2e2f\
                     303132333435363738393a3b3c3d3e3f\
                     404142434445464748494a4b4c4d4e4f",
                );
                let salt = hex_to_vec(
                    "606162636465666768696a6b6c6d6e6f\
                     707172737475767778797a7b7c7d7e7f\
                     808182838485868788898a8b8c8d8e8f\
                     909192939495969798999a9b9c9d9e9f\
                     a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                );
                let info = hex_to_vec(
                    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
                     c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                     d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
                     e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                     f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                );
                let expected_prk =
                    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";
                let expected_okm = "b11e398dc80327a1c8e7f78c596a4934\
                     4f012eda2d4efad8a050cc4c19afa97c\
                     59045a99cac7827271cb41c65e590e09\
                     da3275600c2f09b8367793a9aca3db71\
                     cc30c58179ec3e87c14c01d5c1f3434f\
                     1d87";

                let p = provider();

                let mut prk = Buf::new();
                p.hkdf_extract(HashAlgorithm::SHA256, &salt, &ikm, &mut prk)
                    .unwrap();
                assert_eq!(slice_to_hex(prk.as_ref()), expected_prk);

                let mut okm = Buf::new();
                p.hkdf_expand(HashAlgorithm::SHA256, prk.as_ref(), &info, &mut okm, 82)
                    .unwrap();
                assert_eq!(slice_to_hex(okm.as_ref()), expected_okm);
            }

            #[test]
            fn test_hkdf_sha256_test_case_3() {
                // Test Case 3 - Zero-length salt and info with SHA-256
                let ikm = hex_to_vec("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                let salt = vec![];
                let info = vec![];
                let expected_prk =
                    "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";
                let expected_okm = "8da4e775a563c18f715f802a063c5a31\
                                    b8a11f5c5ee1879ec3454e5f3c738d2d\
                                    9d201395faa4b61a96c8";

                let p = provider();

                let mut prk = Buf::new();
                p.hkdf_extract(HashAlgorithm::SHA256, &salt, &ikm, &mut prk)
                    .unwrap();
                assert_eq!(slice_to_hex(prk.as_ref()), expected_prk);

                let mut okm = Buf::new();
                p.hkdf_expand(HashAlgorithm::SHA256, prk.as_ref(), &info, &mut okm, 42)
                    .unwrap();
                assert_eq!(slice_to_hex(okm.as_ref()), expected_okm);
            }
        }
    };
}

pub use impl_hmac_providers;

/// Build the HkdfLabel structure.
///
/// ```text
/// struct {
///     uint16 length;
///     opaque label<6..255> = prefix + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
pub fn build_hkdf_label(
    prefix: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, String> {
    let full_label_len = prefix.len() + label.len();

    if full_label_len > 255 {
        return Err("Label too long for HKDF-Expand-Label".into());
    }
    if context.len() > 255 {
        return Err("Context too long for HKDF-Expand-Label".into());
    }
    if output_len > 65535 {
        return Err("Output length too large for HKDF-Expand-Label".into());
    }

    let info_len = 2 + 1 + full_label_len + 1 + context.len();
    let mut info = Vec::with_capacity(info_len);

    // uint16 length
    info.extend_from_slice(&(output_len as u16).to_be_bytes());
    // opaque label
    info.push(full_label_len as u8);
    info.extend_from_slice(prefix);
    info.extend_from_slice(label);
    // opaque context
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    Ok(info)
}

// ---------------------------------------------------------------------------
// DimplCryptoDtlsInstance
// ---------------------------------------------------------------------------

/// A DTLS session backed by the dimpl library.
pub struct DimplCryptoDtlsInstance {
    name: &'static str,
    dtls: dimpl::Dtls,
}

impl DimplCryptoDtlsInstance {
    /// Create a new DTLS instance.
    ///
    /// The caller supplies the dimpl [`CryptoProvider`][dimpl::crypto::CryptoProvider]
    /// so this helper stays platform-agnostic.
    pub fn try_new(
        name: &'static str,
        cert: &dimpl::DtlsCertificate,
        now: Instant,
        dtls_version: DtlsVersion,
        is_test: bool,
        crypto_provider: dimpl::crypto::CryptoProvider,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let dimpl_cert = dimpl::DtlsCertificate {
            certificate: cert.certificate.clone(),
            private_key: cert.private_key.clone(),
        };

        // Create a dimpl Config.
        let mut builder = dimpl::Config::builder();
        if is_test {
            // We need the DTLS impl to be deterministic for the BWE tests.
            builder = builder.dangerously_set_rng_seed(42);
        }

        let config = builder
            .with_crypto_provider(crypto_provider)
            .build()
            .map_err(|e| CryptoError::Other(format!("dimpl config creation failed: {e}")))?;

        let config = Arc::new(config);
        let dtls = match dtls_version {
            DtlsVersion::Dtls12 => dimpl::Dtls::new_12(config, dimpl_cert, now),
            DtlsVersion::Dtls13 => dimpl::Dtls::new_13(config, dimpl_cert, now),
            DtlsVersion::Auto => dimpl::Dtls::new_auto(config, dimpl_cert, now),
            #[allow(unreachable_patterns)]
            _ => {
                return Err(CryptoError::Other(format!(
                    "Unsupported DTLS version: {dtls_version}"
                )));
            }
        };

        Ok(Box::new(Self { name, dtls }))
    }
}

impl std::fmt::Debug for DimplCryptoDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(self.name).finish()
    }
}

impl DtlsInstance for DimplCryptoDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.dtls.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), dimpl::Error> {
        self.dtls.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> dimpl::Output<'a> {
        self.dtls.poll_output(buf)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), dimpl::Error> {
        self.dtls.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), dimpl::Error> {
        self.dtls.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.dtls.is_active()
    }
}

// ---------------------------------------------------------------------------
// X.509 / PKCS#8 certificate helpers
// ---------------------------------------------------------------------------

/// Build a self-signed X.509 v3 certificate.
pub fn build_self_signed_certificate<SignFn>(
    common_name: &str,
    serial_number: [u8; 16],
    public_key_bytes: &[u8],
    sign_with_ecdsa_sha256: SignFn,
) -> Result<Vec<u8>, CryptoError>
where
    SignFn: FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>,
{
    let mut tbs_certificate = Vec::new();

    // Version: v3 (encoded as [0] EXPLICIT INTEGER 2)
    let version = encode_explicit_tag(0, &encode_integer(&[2]));
    tbs_certificate.extend_from_slice(&version);

    // Serial number (random)
    tbs_certificate.extend_from_slice(&encode_integer(&serial_number));

    // Signature algorithm: ecdsa-with-SHA256
    let ecdsa_with_sha256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    tbs_certificate.extend_from_slice(&encode_algorithm_identifier(ecdsa_with_sha256_oid));

    // Issuer: CN=WebRTC
    let issuer = encode_name(common_name);
    tbs_certificate.extend_from_slice(&issuer);

    // Validity: 1 year from now
    let validity = encode_validity()?;
    tbs_certificate.extend_from_slice(&validity);

    // Subject: CN=WebRTC (same as issuer for self-signed)
    tbs_certificate.extend_from_slice(&issuer);

    // Subject Public Key Info
    let spki = encode_ec_public_key_info(public_key_bytes)?;
    tbs_certificate.extend_from_slice(&spki);

    let tbs_certificate = encode_sequence(&tbs_certificate);

    // Sign the TBS certificate using the private key directly
    let signature = sign_with_ecdsa_sha256(&tbs_certificate)?;

    // Encode the full certificate
    let ecdsa_with_sha256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
    let sig_algorithm = encode_algorithm_identifier(ecdsa_with_sha256_oid);

    // Signature as BIT STRING (prepend 0x00 for no unused bits)
    let signature_bits = encode_bit_string(&signature);

    // Full certificate SEQUENCE
    let mut signed_certificate = Vec::new();
    signed_certificate.extend_from_slice(&tbs_certificate);
    signed_certificate.extend_from_slice(&sig_algorithm);
    signed_certificate.extend_from_slice(&signature_bits);

    Ok(encode_sequence(&signed_certificate))
}

/// Build a PKCS#8 `PrivateKeyInfo` for an EC P-256 key.
pub fn build_pkcs8(
    private_scalar: &[u8; 32],
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
    let ec_private_key = encode_ec_private_key(private_scalar, public_key_bytes)?;
    let private_key = encode_tag(0x04, &ec_private_key); // OCTET STRING

    Ok(encode_sequence(&[version, algorithm, private_key].concat()))
}

// --- ASN.1 DER encoding helpers (private) ---

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
        // len fits in a single byte
    } else if len < 256 {
        out.push(0x81);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
    }
    out.push(len as u8);
}

fn encode_integer(value: &[u8]) -> Vec<u8> {
    // Skip leading zeros but keep at least one byte
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0 {
        start += 1;
    }

    let value = &value[start..];

    // If high bit is set, prepend 0x00
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

fn encode_algorithm_identifier(oid_bytes: &[u8]) -> Vec<u8> {
    let oid = encode_oid(oid_bytes);
    encode_sequence(&oid)
}

fn encode_name(cn: &str) -> Vec<u8> {
    // CN OID: 2.5.4.3
    let cn_oid = &[0x55, 0x04, 0x03];
    let oid = encode_oid(cn_oid);
    let value = encode_tag(0x0C, cn.as_bytes()); // UTF8String
    let attr_type_value = encode_sequence(&[oid, value].concat());
    let rdn = encode_tag(0x31, &attr_type_value); // SET
    encode_sequence(&rdn)
}

fn encode_validity() -> Result<Vec<u8>, CryptoError> {
    // For simplicity, use fixed dates that are valid
    // Format: YYYYMMDDHHMMSSZ
    let not_before = b"20240101000000Z";
    let not_after = b"20251231235959Z";

    let nb = encode_tag(0x18, not_before); // GeneralizedTime
    let na = encode_tag(0x18, not_after);

    Ok(encode_sequence(&[nb, na].concat()))
}

fn encode_ec_public_key_info(public_key_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // OID: 1.2.840.10045.2.1 (ecPublicKey)
    let ec_public_key_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    // OID: 1.2.840.10045.3.1.7 (prime256v1/secp256r1)
    let prime256v1_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let algorithm =
        encode_sequence(&[encode_oid(ec_public_key_oid), encode_oid(prime256v1_oid)].concat());

    let public_key_bits = encode_bit_string(public_key_bytes);

    Ok(encode_sequence(&[algorithm, public_key_bits].concat()))
}

fn encode_bit_string(data: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // No unused bits
    content.extend_from_slice(data);
    encode_tag(0x03, &content)
}

fn encode_ec_private_key(
    private_scalar: &[u8],
    public_key_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let version = encode_integer(&[1]);
    let private_key = encode_tag(0x04, private_scalar); // OCTET STRING

    // Parameters: prime256v1 OID
    let prime256v1_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let params = encode_explicit_tag(0, &encode_oid(prime256v1_oid));

    // Public key as [1] BIT STRING
    let public_key_bits = encode_bit_string(public_key_bytes);
    let public_key = encode_explicit_tag(1, &public_key_bits);

    Ok(encode_sequence(
        &[version, private_key, params, public_key].concat(),
    ))
}
