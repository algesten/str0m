//! Certificate generation routines.
//!

use str0m_proto::crypto::CryptoError;

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
