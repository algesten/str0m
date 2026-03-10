//! HKDF implementation using OpenSSL HMAC for TLS 1.3 key derivation.

use dimpl::crypto::{Buf, HashAlgorithm, HkdfProvider};

use openssl::hash::MessageDigest;

#[derive(Debug)]
pub(super) struct OsslHkdfProvider;

/// Compute HMAC for the given hash algorithm using OpenSSL.
fn hmac(hash: HashAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let md = match hash {
        HashAlgorithm::SHA256 => MessageDigest::sha256(),
        HashAlgorithm::SHA384 => MessageDigest::sha384(),
        _ => return Err(format!("Unsupported hash for HKDF: {hash:?}")),
    };
    super::hmac_openssl(md, key, data)
}

impl HkdfProvider for OsslHkdfProvider {
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
        // SHA-384 (48 bytes) is the largest hash output we support.
        let zero_salt = [0u8; 48];
        let actual_salt = if salt.is_empty() {
            &zero_salt[..hash_len]
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
        let hash_len = hash.output_len();
        let n = output_len.div_ceil(hash_len);
        if n > 255 {
            return Err("HKDF output too long".into());
        }

        let mut t_prev: Vec<u8> = Vec::new();
        let mut okm = Vec::with_capacity(output_len);
        let mut input = Vec::with_capacity(hash_len + info.len() + 1);

        for i in 1..=n {
            input.clear();
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

    let info_len = 2 + 1 + full_label_len + 1 + context.len();
    let mut info = Vec::with_capacity(info_len);

    // uint16 length
    let len_u16 = u16::try_from(output_len)
        .map_err(|_| format!("Output length {output_len} exceeds u16::MAX"))?;
    info.extend_from_slice(&len_u16.to_be_bytes());
    // opaque label
    info.push(full_label_len as u8);
    info.extend_from_slice(prefix);
    info.extend_from_slice(label);
    // opaque context
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    Ok(info)
}

pub(super) static HKDF_PROVIDER: OsslHkdfProvider = OsslHkdfProvider;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dimpl_provider::test_utils::{hex_to_vec, to_hex};

    // RFC 5869 Test Case 1 (SHA-256)
    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = hex_to_vec("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_vec("000102030405060708090a0b0c");
        let info = hex_to_vec("f0f1f2f3f4f5f6f7f8f9");
        let expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        let expected_okm =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

        let provider = OsslHkdfProvider;
        let mut prk = Buf::new();
        provider
            .hkdf_extract(HashAlgorithm::SHA256, &salt, &ikm, &mut prk)
            .unwrap();
        assert_eq!(to_hex(&prk), expected_prk);

        let mut okm = Buf::new();
        provider
            .hkdf_expand(HashAlgorithm::SHA256, &prk, &info, &mut okm, 42)
            .unwrap();
        assert_eq!(to_hex(&okm), expected_okm);
    }

    // RFC 5869 Test Case 2 (SHA-256, longer inputs)
    #[test]
    fn hkdf_rfc5869_case2() {
        let ikm = hex_to_vec(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        );
        let salt = hex_to_vec(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        );
        let info = hex_to_vec(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        let expected_prk = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";
        let expected_okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87";

        let provider = OsslHkdfProvider;
        let mut prk = Buf::new();
        provider
            .hkdf_extract(HashAlgorithm::SHA256, &salt, &ikm, &mut prk)
            .unwrap();
        assert_eq!(to_hex(&prk), expected_prk);

        let mut okm = Buf::new();
        provider
            .hkdf_expand(HashAlgorithm::SHA256, &prk, &info, &mut okm, 82)
            .unwrap();
        assert_eq!(to_hex(&okm), expected_okm);
    }

    // RFC 5869 Test Case 3 (SHA-256, zero-length salt/info)
    #[test]
    fn hkdf_rfc5869_case3() {
        let ikm = hex_to_vec("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let expected_prk = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";
        let expected_okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8";

        let provider = OsslHkdfProvider;
        let mut prk = Buf::new();
        provider
            .hkdf_extract(HashAlgorithm::SHA256, &[], &ikm, &mut prk)
            .unwrap();
        assert_eq!(to_hex(&prk), expected_prk);

        let mut okm = Buf::new();
        provider
            .hkdf_expand(HashAlgorithm::SHA256, &prk, &[], &mut okm, 42)
            .unwrap();
        assert_eq!(to_hex(&okm), expected_okm);
    }
}
