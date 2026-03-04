//! Key exchange group implementations for Android using JNI.

use dimpl::crypto::Buf;
use dimpl::crypto::{ActiveKeyExchange, NamedGroup, SupportedKxGroup};

use crate::jni_crypto;

/// ECDHE key exchange implementation using Android JNI.
struct EcdhKeyExchange {
    private_key_der: Vec<u8>,
    public_key_bytes: Buf,
    group: NamedGroup,
}

impl std::fmt::Debug for EcdhKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.group {
            NamedGroup::Secp256r1 => f
                .debug_struct("EcdhKeyExchange::P256")
                .field("public_key_len", &self.public_key_bytes.len())
                .finish_non_exhaustive(),
            NamedGroup::Secp384r1 => f
                .debug_struct("EcdhKeyExchange::P384")
                .field("public_key_len", &self.public_key_bytes.len())
                .finish_non_exhaustive(),
            _ => f
                .debug_struct("EcdhKeyExchange::Unknown")
                .finish_non_exhaustive(),
        }
    }
}

impl EcdhKeyExchange {
    fn new(group: NamedGroup, mut buf: Buf) -> Result<Self, String> {
        match group {
            NamedGroup::Secp256r1 => {
                // Generate P-256 key pair
                let key_pair = jni_crypto::generate_ec_key_pair_p256()
                    .map_err(|e| format!("Failed to generate EC key pair: {e}"))?;

                buf.clear();
                buf.extend_from_slice(&key_pair.public_key_bytes);

                Ok(Self {
                    private_key_der: key_pair.private_key_der,
                    public_key_bytes: buf,
                    group,
                })
            }
            NamedGroup::Secp384r1 => {
                // P-384 would need a separate implementation
                // For now, we only support P-256
                Err("P-384 not yet supported".to_string())
            }
            _ => Err(format!("Unsupported group: {group:?}")),
        }
    }
}

impl ActiveKeyExchange for EcdhKeyExchange {
    fn pub_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), String> {
        let shared_secret = jni_crypto::ecdh_key_agreement(&self.private_key_der, peer_pub)
            .map_err(|e| format!("ECDH key agreement failed: {e}"))?;

        out.clear();
        out.extend_from_slice(&shared_secret);
        Ok(())
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

/// P-256 (secp256r1) ECDH key exchange group.
#[derive(Debug)]
struct Secp256r1;

impl SupportedKxGroup for Secp256r1 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp256r1
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp256r1, buf)?))
    }
}

static SECP256R1: Secp256r1 = Secp256r1;

pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&SECP256R1];
