//! HKDF implementation using Apple CommonCrypto HMAC for TLS 1.3 key derivation.

use dimpl::crypto::{Buf, HashAlgorithm, HkdfProvider};

#[derive(Debug)]
pub(super) struct AppleHkdfProvider;

/// Compute HMAC for the given hash algorithm.
fn hmac(hash: HashAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    match hash {
        HashAlgorithm::SHA256 => {
            let result = apple_cryptokit::hmac_sha256(key, data).map_err(|e| format!("{e:?}"))?;
            Ok(result.to_vec())
        }
        HashAlgorithm::SHA384 => {
            let result = apple_cryptokit::authentication::sha384::hmac_sha384(key, data)
                .map_err(|e| format!("{e:?}"))?;
            Ok(result.to_vec())
        }
        _ => Err(format!("Unsupported hash for HKDF: {hash:?}")),
    }
}

impl HkdfProvider for AppleHkdfProvider {
    fn hkdf_extract(
        &self,
        hash: HashAlgorithm,
        salt: &[u8],
        ikm: &[u8],
        out: &mut Buf,
    ) -> Result<(), String> {
        out.clear();

        // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
        // If salt is empty, use a zero-filled salt of hash length
        let hash_len = hash.output_len();
        let zero_salt: Vec<u8>;
        let actual_salt = if salt.is_empty() {
            zero_salt = vec![0u8; hash_len];
            &zero_salt[..]
        } else {
            salt
        };

        let prk = hmac(hash, actual_salt, ikm)?;
        out.extend_from_slice(&prk);
        Ok(())
    }

    fn hkdf_expand(
        &self,
        hash: HashAlgorithm,
        prk: &[u8],
        info: &[u8],
        out: &mut Buf,
        output_len: usize,
    ) -> Result<(), String> {
        out.clear();

        // HKDF-Expand per RFC 5869 Section 2.3
        // T(0) = empty
        // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)  for i = 1..N
        let hash_len = hash.output_len();
        let n = output_len.div_ceil(hash_len);
        if n > 255 {
            return Err("HKDF output too long".into());
        }

        let mut t_prev = Vec::new();
        let mut okm = Vec::with_capacity(output_len);

        for i in 1..=n {
            let mut input = Vec::with_capacity(t_prev.len() + info.len() + 1);
            input.extend_from_slice(&t_prev);
            input.extend_from_slice(info);
            input.push(i as u8);

            t_prev = hmac(hash, prk, &input)?;
            okm.extend_from_slice(&t_prev);
        }

        okm.truncate(output_len);
        out.extend_from_slice(&okm);
        Ok(())
    }

    fn hkdf_expand_label(
        &self,
        hash: HashAlgorithm,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut Buf,
        output_len: usize,
    ) -> Result<(), String> {
        // HkdfLabel per RFC 8446 Section 7.1 with "tls13 " prefix
        let info = build_hkdf_label(b"tls13 ", label, context, output_len)?;
        self.hkdf_expand(hash, secret, &info, out, output_len)
    }

    fn hkdf_expand_label_dtls13(
        &self,
        hash: HashAlgorithm,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut Buf,
        output_len: usize,
    ) -> Result<(), String> {
        // HkdfLabel per RFC 9147 with "dtls13" prefix (no space)
        let info = build_hkdf_label(b"dtls13", label, context, output_len)?;
        self.hkdf_expand(hash, secret, &info, out, output_len)
    }
}

/// Build the HkdfLabel structure.
///
/// ```text
/// struct {
///     uint16 length;
///     opaque label<6..255> = prefix + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
fn build_hkdf_label(
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

pub(super) static HKDF_PROVIDER: AppleHkdfProvider = AppleHkdfProvider;
