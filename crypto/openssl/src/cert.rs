use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder};

use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::dtls::DtlsCert;

pub(crate) fn generate_certificate_impl() -> Result<DtlsCert, CryptoError> {
    // Generate EC key pair using P-256 curve
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    // Build the X509 certificate
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?; // X509 v3

    // Generate random serial number
    let mut serial = BigNum::new()?;
    serial.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
    builder.set_serial_number(serial.to_asn1_integer()?.as_ref())?;

    // Set validity period (1 year)
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Set subject name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", "WebRTC")?;
    let name = name_builder.build();
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;

    builder.set_pubkey(&pkey)?;

    // Add extensions
    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(basic_constraints)?;

    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_encipherment()
        .build()?;
    builder.append_extension(key_usage)?;

    let ext_key_usage = ExtendedKeyUsage::new()
        .server_auth()
        .client_auth()
        .build()?;
    builder.append_extension(ext_key_usage)?;

    // Sign the certificate
    builder.sign(&pkey, MessageDigest::sha256())?;

    let cert = builder.build();

    // Convert to DER format
    let certificate = cert.to_der()?;
    let private_key = pkey.private_key_to_der()?;

    Ok(DtlsCert {
        certificate,
        private_key,
    })
}
