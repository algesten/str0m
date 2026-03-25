//! Signing and key loading implementations using Windows CNG BCrypt ECDSA.

use std::str;

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, KeyProvider};
use dimpl::crypto::{SignatureAlgorithm, SignatureVerifier, SigningKey as SigningKeyTrait};

use windows::Win32::Security::Cryptography::BCRYPT_ECCPRIVATE_BLOB;
use windows::Win32::Security::Cryptography::BCRYPT_ECCPUBLIC_BLOB;
use windows::Win32::Security::Cryptography::BCRYPT_ECDSA_P256_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_ECDSA_P384_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_FLAGS;
use windows::Win32::Security::Cryptography::BCRYPT_KEY_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_SHA256_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_SHA384_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCryptHash;
use windows::Win32::Security::Cryptography::BCryptImportKeyPair;
use windows::Win32::Security::Cryptography::BCryptSignHash;
use windows::Win32::Security::Cryptography::BCryptVerifySignature;
use windows::core::Owned;

use crate::WinCryptoError;

// Well-known OID values (raw DER content bytes, without tag/length).
/// ecPublicKey: 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// prime256v1 (P-256): 1.2.840.10045.3.1.7
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// secp384r1 (P-384): 1.3.132.0.34
const OID_SECP384R1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];

#[derive(Clone, Copy, Debug)]
enum EcCurve {
    P256,
    P384,
}

/// ECDSA signing key implementation using Windows CNG.
struct EcdsaSigningKey {
    key_handle: Owned<BCRYPT_KEY_HANDLE>,
    curve: EcCurve,
}

// SAFETY: `BCRYPT_KEY_HANDLE` is an opaque CNG handle documented by Microsoft
// Learn for the BCrypt APIs; this wrapper never dereferences it directly and
// only passes it back to those APIs.
// Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/
unsafe impl Send for EcdsaSigningKey {}
// SAFETY: `BCRYPT_KEY_HANDLE` is an opaque CNG handle documented by Microsoft
// Learn for the BCrypt APIs; this wrapper never dereferences it directly and
// only passes it back to those APIs.
// Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/
unsafe impl Sync for EcdsaSigningKey {}

impl std::fmt::Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaSigningKey")
            .field("curve", &self.curve)
            .finish_non_exhaustive()
    }
}

impl SigningKeyTrait for EcdsaSigningKey {
    fn sign(&mut self, data: &[u8], out: &mut Buf) -> Result<(), String> {
        // Hash the data.
        let (hash_alg, hash_len) = match self.curve {
            EcCurve::P256 => (BCRYPT_SHA256_ALG_HANDLE, 32usize),
            EcCurve::P384 => (BCRYPT_SHA384_ALG_HANDLE, 48usize),
        };

        let mut hash = vec![0u8; hash_len];
        // SAFETY: Microsoft Learn documents `BCryptHash` as borrowing the input
        // and output buffers only for the duration of the call; both outlive
        // this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcrypthash
        unsafe {
            WinCryptoError::from_ntstatus(BCryptHash(hash_alg, None, data, &mut hash))
                .map_err(|e| format!("Hash failed: {e}"))?;
        }

        // Sign the hash.
        let sig_size = match self.curve {
            EcCurve::P256 => 64usize, // 32 + 32
            EcCurve::P384 => 96usize, // 48 + 48
        };
        let mut raw_sig = vec![0u8; sig_size];
        let mut sig_len = 0u32;

        // SAFETY: Microsoft Learn documents `BCryptSignHash` as borrowing the
        // key handle, hash, and output buffer only for the duration of the
        // call; all three outlive this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptsignhash
        unsafe {
            WinCryptoError::from_ntstatus(BCryptSignHash(
                *self.key_handle,
                None,
                &hash,
                Some(&mut raw_sig),
                &mut sig_len,
                BCRYPT_FLAGS(0),
            ))
            .map_err(|e| format!("BCryptSignHash failed: {e}"))?;
        }

        raw_sig.truncate(sig_len as usize);

        // Convert raw (r,s) to DER-encoded ECDSA-Sig-Value.
        let der_sig = raw_rs_to_der(&raw_sig)?;

        out.clear();
        out.extend_from_slice(&der_sig);
        Ok(())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self.curve {
            EcCurve::P256 => HashAlgorithm::SHA256,
            EcCurve::P384 => HashAlgorithm::SHA384,
        }
    }
}

/// ECDSA key provider using Windows CNG.
#[derive(Debug)]
pub(super) struct WinCngKeyProvider;

impl KeyProvider for WinCngKeyProvider {
    fn load_private_key(&self, key_der: &[u8]) -> Result<Box<dyn SigningKeyTrait>, String> {
        // Try PEM format first.
        if let Ok(pem_str) = str::from_utf8(key_der) {
            if pem_str.contains("-----BEGIN") {
                if let Ok(decoded) = decode_pem(pem_str) {
                    return self.load_private_key(&decoded);
                }
            }
        }

        // Try PKCS#8 unwrap, fall back to treating as raw SEC1.
        let sec1_der = try_unwrap_pkcs8(key_der).unwrap_or_else(|| key_der.to_vec());

        // Parse SEC1 ECPrivateKey.
        let (curve_hint, private_key_bytes, public_key_opt) = parse_ec_private_key(&sec1_der)?;

        let curve = if let Some(c) = curve_hint {
            c
        } else if private_key_bytes.len() == 32 {
            EcCurve::P256
        } else if private_key_bytes.len() == 48 {
            EcCurve::P384
        } else {
            return Err(format!(
                "Could not determine EC curve from key length: {}",
                private_key_bytes.len()
            ));
        };

        let public_key_bytes = public_key_opt
            .ok_or_else(|| "EC private key missing public key component".to_string())?;

        let coord_size = match curve {
            EcCurve::P256 => 32usize,
            EcCurve::P384 => 48usize,
        };

        let expected_pub_len = 1 + 2 * coord_size;
        if public_key_bytes.len() != expected_pub_len || public_key_bytes[0] != 0x04 {
            return Err(format!(
                "Unexpected public key length: {} (expected {})",
                public_key_bytes.len(),
                expected_pub_len
            ));
        }

        let x = &public_key_bytes[1..1 + coord_size];
        let y = &public_key_bytes[1 + coord_size..];
        let d = &private_key_bytes;

        let (alg_handle, magic) = match curve {
            EcCurve::P256 => (
                BCRYPT_ECDSA_P256_ALG_HANDLE,
                0x32534345u32, // BCRYPT_ECDSA_PRIVATE_P256_MAGIC
            ),
            EcCurve::P384 => (
                BCRYPT_ECDSA_P384_ALG_HANDLE,
                0x34534345u32, // BCRYPT_ECDSA_PRIVATE_P384_MAGIC
            ),
        };

        // Build BCRYPT_ECCKEY_BLOB for private key.
        let header_size = 8;
        let mut blob = Vec::with_capacity(header_size + 3 * coord_size);
        blob.extend_from_slice(&magic.to_le_bytes());
        blob.extend_from_slice(&(coord_size as u32).to_le_bytes());

        // Pad/truncate X, Y, D to coord_size.
        pad_to(&mut blob, x, coord_size);
        pad_to(&mut blob, y, coord_size);
        pad_to(&mut blob, d, coord_size);

        // SAFETY: Microsoft Learn documents `BCryptImportKeyPair` as borrowing
        // the key blob and output handle only for the duration of the call;
        // both outlive this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair
        let key_handle = unsafe {
            let mut key_handle = Owned::new(BCRYPT_KEY_HANDLE::default());
            WinCryptoError::from_ntstatus(BCryptImportKeyPair(
                alg_handle,
                None,
                BCRYPT_ECCPRIVATE_BLOB,
                &mut *key_handle,
                &blob,
                0,
            ))
            .map_err(|e| format!("BCryptImportKeyPair failed: {e}"))?;
            key_handle
        };

        Ok(Box::new(EcdsaSigningKey { key_handle, curve }))
    }
}

// Pad or truncate src to exactly `size` bytes, left-padded with zeros.
fn pad_to(dst: &mut Vec<u8>, src: &[u8], size: usize) {
    if src.len() >= size {
        dst.extend_from_slice(&src[src.len() - size..]);
    } else {
        let pad = size - src.len();
        dst.extend(std::iter::repeat_n(0u8, pad));
        dst.extend_from_slice(src);
    }
}

/// Signature verifier implementation using Windows CNG.
#[derive(Debug)]
pub(super) struct WinCngSignatureVerifier;

impl SignatureVerifier for WinCngSignatureVerifier {
    fn verify_signature(
        &self,
        cert_der: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlgorithm,
        sig_alg: SignatureAlgorithm,
    ) -> Result<(), String> {
        if sig_alg != SignatureAlgorithm::ECDSA {
            return Err(format!("Unsupported signature algorithm: {sig_alg:?}"));
        }

        let (alg_oid, pubkey_bytes) = extract_spki_from_cert(cert_der)?;

        if alg_oid != OID_EC_PUBLIC_KEY {
            return Err("Unsupported public key algorithm OID".into());
        }

        // Verify uncompressed EC point format (0x04 prefix).
        if pubkey_bytes.is_empty() || pubkey_bytes[0] != 0x04 {
            return Err("EC public key is not in uncompressed format (0x04)".into());
        }

        // Determine key size from public key length.
        let (alg_handle, coord_size, magic) = if pubkey_bytes.len() == 65 {
            (
                BCRYPT_ECDSA_P256_ALG_HANDLE,
                32usize,
                0x31534345u32, // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
            )
        } else if pubkey_bytes.len() == 97 {
            (
                BCRYPT_ECDSA_P384_ALG_HANDLE,
                48usize,
                0x33534345u32, // BCRYPT_ECDSA_PUBLIC_P384_MAGIC
            )
        } else {
            return Err(format!(
                "Unsupported EC public key size: {} bytes",
                pubkey_bytes.len()
            ));
        };

        // Hash the data.
        let (hash_bcrypt_alg, hash_len) = match hash_alg {
            HashAlgorithm::SHA256 => (BCRYPT_SHA256_ALG_HANDLE, 32usize),
            HashAlgorithm::SHA384 => (BCRYPT_SHA384_ALG_HANDLE, 48usize),
            _ => {
                return Err(format!(
                    "Unsupported hash algorithm for ECDSA: {hash_alg:?}"
                ));
            }
        };

        let mut hash = vec![0u8; hash_len];
        // SAFETY: Microsoft Learn documents `BCryptHash` as borrowing the input
        // and output buffers only for the duration of the call; both outlive
        // this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcrypthash
        unsafe {
            WinCryptoError::from_ntstatus(BCryptHash(hash_bcrypt_alg, None, data, &mut hash))
                .map_err(|e| format!("Hash failed: {e}"))?;
        }

        // Import the public key.
        let header_size = 8;
        let mut blob = Vec::with_capacity(header_size + 2 * coord_size);
        blob.extend_from_slice(&magic.to_le_bytes());
        blob.extend_from_slice(&(coord_size as u32).to_le_bytes());
        blob.extend_from_slice(&pubkey_bytes[1..]); // Skip 0x04 prefix

        // SAFETY: Microsoft Learn documents `BCryptImportKeyPair` as borrowing
        // the key blob and output handle only for the duration of the call;
        // both outlive this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair
        let key_handle = unsafe {
            let mut key_handle = Owned::new(BCRYPT_KEY_HANDLE::default());
            WinCryptoError::from_ntstatus(BCryptImportKeyPair(
                alg_handle,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                &mut *key_handle,
                &blob,
                0,
            ))
            .map_err(|e| format!("Import public key failed: {e}"))?;
            key_handle
        };

        // Convert DER signature to raw (r,s) format.
        let raw_sig = der_to_raw_rs(signature, coord_size)?;

        // Verify.
        // SAFETY: Microsoft Learn documents `BCryptVerifySignature` as
        // borrowing the key handle, hash, and signature buffers only for the
        // duration of the call; all three outlive this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptverifysignature
        unsafe {
            WinCryptoError::from_ntstatus(BCryptVerifySignature(
                *key_handle,
                None,
                &hash,
                &raw_sig,
                BCRYPT_FLAGS(0),
            ))
            .map_err(|e| format!("ECDSA signature verification failed: {e}"))?;
        }

        Ok(())
    }
}

/// Convert raw (r || s) to DER-encoded ECDSA-Sig-Value.
pub(crate) fn raw_rs_to_der(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() % 2 != 0 {
        return Err("Raw signature length must be even".into());
    }
    let half = raw.len() / 2;
    let r = &raw[..half];
    let s = &raw[half..];

    let r_der = encode_der_integer(r);
    let s_der = encode_der_integer(s);

    let mut content = Vec::new();
    content.extend_from_slice(&r_der);
    content.extend_from_slice(&s_der);

    let mut result = vec![0x30]; // SEQUENCE tag
    encode_der_length(content.len(), &mut result);
    result.extend_from_slice(&content);

    Ok(result)
}

/// Convert DER-encoded ECDSA-Sig-Value to raw (r || s).
fn der_to_raw_rs(der: &[u8], coord_size: usize) -> Result<Vec<u8>, String> {
    // Parse outer SEQUENCE.
    let (tag, seq_content, _) = parse_tlv(der)?;
    if tag != 0x30 {
        return Err("Invalid DER signature: not a SEQUENCE".into());
    }

    // Parse r INTEGER.
    let (tag, r_bytes, rest) = parse_tlv(seq_content)?;
    if tag != 0x02 {
        return Err("Invalid DER signature: r not INTEGER".into());
    }

    // Parse s INTEGER.
    let (tag, s_bytes, _) = parse_tlv(rest)?;
    if tag != 0x02 {
        return Err("Invalid DER signature: s not INTEGER".into());
    }

    // Convert to fixed-size (r || s).
    let mut raw = vec![0u8; coord_size * 2];
    copy_integer_to_fixed(&mut raw[..coord_size], r_bytes)?;
    copy_integer_to_fixed(&mut raw[coord_size..], s_bytes)?;

    Ok(raw)
}

// Copy a DER integer (possibly with leading zero) into a fixed-size buffer, right-aligned.
fn copy_integer_to_fixed(dst: &mut [u8], src: &[u8]) -> Result<(), String> {
    // Skip leading zeros in the DER integer.
    let mut start = 0;
    while start < src.len() && src[start] == 0 && (src.len() - start) > dst.len() {
        start += 1;
    }
    let meaningful = &src[start..];
    if meaningful.len() <= dst.len() {
        let offset = dst.len() - meaningful.len();
        dst[offset..].copy_from_slice(meaningful);
        Ok(())
    } else {
        Err(format!(
            "DER integer too large: {} bytes for {}-byte field",
            meaningful.len(),
            dst.len()
        ))
    }
}

fn encode_der_integer(value: &[u8]) -> Vec<u8> {
    if value.is_empty() {
        // Encode zero.
        return vec![0x02, 0x01, 0x00];
    }

    // Skip leading zeros but keep at least one byte.
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0 {
        start += 1;
    }
    let trimmed = &value[start..];

    let mut result = vec![0x02]; // INTEGER tag
    if trimmed[0] & 0x80 != 0 {
        // Need leading zero.
        encode_der_length(trimmed.len() + 1, &mut result);
        result.push(0x00);
    } else {
        encode_der_length(trimmed.len(), &mut result);
    }
    result.extend_from_slice(trimmed);
    result
}

fn encode_der_length(len: usize, out: &mut Vec<u8>) {
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

fn parse_der_length(data: &[u8]) -> Result<(usize, &[u8]), String> {
    if data.is_empty() {
        return Err("DER: unexpected end of data".into());
    }
    if data[0] < 128 {
        Ok((data[0] as usize, &data[1..]))
    } else if data[0] == 0x81 {
        if data.len() < 2 {
            return Err("DER: truncated length".into());
        }
        Ok((data[1] as usize, &data[2..]))
    } else if data[0] == 0x82 {
        if data.len() < 3 {
            return Err("DER: truncated length".into());
        }
        Ok((((data[1] as usize) << 8) | (data[2] as usize), &data[3..]))
    } else {
        Err("DER: unsupported length encoding".into())
    }
}

// ============================================================================
// Minimal DER parsing helpers (replaces der/pkcs8/sec1/spki/x509-cert crates)
// ============================================================================

/// Parse a DER TLV (Tag-Length-Value). Returns (tag, value, remaining_bytes).
fn parse_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    if data.is_empty() {
        return Err("DER: unexpected end of data".into());
    }
    let tag = data[0];
    let (len, after_len) = parse_der_length(&data[1..])?;
    if after_len.len() < len {
        return Err(format!(
            "DER: truncated (need {len}, have {})",
            after_len.len()
        ));
    }
    Ok((tag, &after_len[..len], &after_len[len..]))
}

/// Decode PEM to DER bytes.
fn decode_pem(pem: &str) -> Result<Vec<u8>, String> {
    use windows::Win32::Security::Cryptography::{CRYPT_STRING_BASE64HEADER, CryptStringToBinaryA};

    // CryptStringToBinaryA handles PEM headers/footers and base64 decoding.
    let pem_bytes = pem.as_bytes();
    let mut der_len = 0u32;

    // First call: get required buffer size.
    // SAFETY: Microsoft Learn documents `CryptStringToBinaryA` as allowing a
    // null output buffer when querying the required decoded size.
    // Docs: https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinarya
    unsafe {
        CryptStringToBinaryA(
            pem_bytes,
            CRYPT_STRING_BASE64HEADER,
            None,
            &mut der_len,
            None,
            None,
        )
        .map_err(|e| format!("PEM decode (size query): {e}"))?;
    }

    let mut der = vec![0u8; der_len as usize];

    // Second call: decode into buffer.
    // SAFETY: Microsoft Learn documents `CryptStringToBinaryA` as writing into
    // the caller-provided output buffer for the duration of the call; `der`
    // was sized from the preceding length query and outlives this block.
    // Docs: https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinarya
    unsafe {
        CryptStringToBinaryA(
            pem_bytes,
            CRYPT_STRING_BASE64HEADER,
            Some(der.as_mut_ptr()),
            &mut der_len,
            None,
            None,
        )
        .map_err(|e| format!("PEM decode: {e}"))?;
    }

    der.truncate(der_len as usize);
    Ok(der)
}

/// Try to unwrap PKCS#8 PrivateKeyInfo, returning the inner private key DER.
/// Returns None if the data doesn't look like PKCS#8 for an EC key.
fn try_unwrap_pkcs8(der: &[u8]) -> Option<Vec<u8>> {
    // SEQUENCE { version INTEGER, algorithm SEQUENCE, privateKey OCTET STRING }
    let (tag, seq_content, _) = parse_tlv(der).ok()?;
    if tag != 0x30 {
        return None;
    }

    // version INTEGER.
    let (tag, _version, rest) = parse_tlv(seq_content).ok()?;
    if tag != 0x02 {
        return None;
    }

    // algorithm SEQUENCE — verify it contains ecPublicKey OID.
    let (tag, alg_content, rest) = parse_tlv(rest).ok()?;
    if tag != 0x30 {
        return None;
    }
    let (tag, alg_oid, _) = parse_tlv(alg_content).ok()?;
    if tag != 0x06 || alg_oid != OID_EC_PUBLIC_KEY {
        return None;
    }

    // privateKey OCTET STRING.
    let (tag, private_key, _) = parse_tlv(rest).ok()?;
    if tag != 0x04 {
        return None;
    }

    Some(private_key.to_vec())
}

/// Parse SEC1 ECPrivateKey. Returns (curve, private_key, public_key).
#[allow(clippy::type_complexity)]
fn parse_ec_private_key(der: &[u8]) -> Result<(Option<EcCurve>, Vec<u8>, Option<Vec<u8>>), String> {
    let (tag, seq_content, _) = parse_tlv(der)?;
    if tag != 0x30 {
        return Err("ECPrivateKey: not a SEQUENCE".into());
    }

    // version INTEGER (should be 1).
    let (tag, _version, rest) = parse_tlv(seq_content)?;
    if tag != 0x02 {
        return Err("ECPrivateKey: version not INTEGER".into());
    }

    // privateKey OCTET STRING.
    let (tag, private_key, mut rest) = parse_tlv(rest)?;
    if tag != 0x04 {
        return Err("ECPrivateKey: privateKey not OCTET STRING".into());
    }

    let mut curve = None;
    let mut public_key = None;

    // Optional context-tagged fields.
    while !rest.is_empty() {
        let (tag, content, remaining) = parse_tlv(rest)?;
        match tag {
            0xA0 => {
                // [0] parameters — should contain an OID.
                let (tag, oid_bytes, _) = parse_tlv(content)?;
                if tag == 0x06 {
                    curve = oid_to_curve(oid_bytes);
                }
            }
            0xA1 => {
                // [1] publicKey — BIT STRING.
                let (tag, bs_content, _) = parse_tlv(content)?;
                if tag == 0x03 && bs_content.len() > 1 {
                    if bs_content[0] != 0 {
                        return Err("ECPrivateKey: BIT STRING has non-zero unused bits".into());
                    }
                    public_key = Some(bs_content[1..].to_vec());
                }
            }
            _ => {} // Skip unknown.
        }
        rest = remaining;
    }

    Ok((curve, private_key.to_vec(), public_key))
}

// Map raw OID value bytes to an EcCurve.
fn oid_to_curve(oid_bytes: &[u8]) -> Option<EcCurve> {
    if oid_bytes == OID_PRIME256V1 {
        Some(EcCurve::P256)
    } else if oid_bytes == OID_SECP384R1 {
        Some(EcCurve::P384)
    } else {
        None
    }
}

/// Extract SubjectPublicKeyInfo from a DER-encoded X.509 certificate.
/// Returns (algorithm_oid_bytes, public_key_bytes) where public_key_bytes
/// is the BIT STRING content without the unused-bits byte.
fn extract_spki_from_cert(cert_der: &[u8]) -> Result<(&[u8], &[u8]), String> {
    // Certificate SEQUENCE
    let (tag, cert_content, _) = parse_tlv(cert_der)?;
    if tag != 0x30 {
        return Err("Certificate: not a SEQUENCE".into());
    }

    // TBSCertificate SEQUENCE
    let (tag, tbs_content, _) = parse_tlv(cert_content)?;
    if tag != 0x30 {
        return Err("TBSCertificate: not a SEQUENCE".into());
    }

    let mut pos = tbs_content;

    // [0] version — optional context-specific tag
    if !pos.is_empty() && pos[0] == 0xA0 {
        let (_, _, rest) = parse_tlv(pos)?;
        pos = rest;
    }

    // serialNumber INTEGER
    let (tag, _, rest) = parse_tlv(pos)?;
    if tag != 0x02 {
        return Err("TBS: serialNumber not INTEGER".into());
    }
    pos = rest;

    // signature AlgorithmIdentifier SEQUENCE
    let (tag, _, rest) = parse_tlv(pos)?;
    if tag != 0x30 {
        return Err("TBS: signature not SEQUENCE".into());
    }
    pos = rest;

    // issuer Name SEQUENCE
    let (tag, _, rest) = parse_tlv(pos)?;
    if tag != 0x30 {
        return Err("TBS: issuer not SEQUENCE".into());
    }
    pos = rest;

    // validity SEQUENCE
    let (tag, _, rest) = parse_tlv(pos)?;
    if tag != 0x30 {
        return Err("TBS: validity not SEQUENCE".into());
    }
    pos = rest;

    // subject Name SEQUENCE
    let (tag, _, rest) = parse_tlv(pos)?;
    if tag != 0x30 {
        return Err("TBS: subject not SEQUENCE".into());
    }
    pos = rest;

    // subjectPublicKeyInfo SEQUENCE
    let (tag, spki_content, _) = parse_tlv(pos)?;
    if tag != 0x30 {
        return Err("SPKI: not a SEQUENCE".into());
    }

    // algorithm AlgorithmIdentifier SEQUENCE
    let (tag, alg_content, rest) = parse_tlv(spki_content)?;
    if tag != 0x30 {
        return Err("SPKI algorithm: not a SEQUENCE".into());
    }

    // Extract OID from algorithm
    let (tag, oid_bytes, _) = parse_tlv(alg_content)?;
    if tag != 0x06 {
        return Err("SPKI: algorithm OID not found".into());
    }

    // subjectPublicKey BIT STRING
    let (tag, bs_content, _) = parse_tlv(rest)?;
    if tag != 0x03 {
        return Err("SPKI: publicKey not BIT STRING".into());
    }
    if bs_content.len() < 2 {
        return Err("SPKI: BIT STRING too short".into());
    }
    if bs_content[0] != 0 {
        return Err("SPKI: BIT STRING has non-zero unused bits".into());
    }

    Ok((oid_bytes, &bs_content[1..]))
}

pub(super) static KEY_PROVIDER: WinCngKeyProvider = WinCngKeyProvider;
pub(super) static SIGNATURE_VERIFIER: WinCngSignatureVerifier = WinCngSignatureVerifier;
