//! X25519 key exchange using OpenSSL.
//!
//! This module is compiled out when the `fips140` feature is enabled,
//! since X25519 is not NIST approved (SP 800-56A).

use dimpl::crypto::{ActiveKeyExchange, Buf, NamedGroup, SupportedKxGroup};

use openssl::pkey::PKey;

/// X25519 key exchange group.
#[derive(Debug)]
pub(super) struct X25519;

impl SupportedKxGroup for X25519 {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(X25519KeyExchange::new(buf)?))
    }
}

/// X25519 key exchange using OpenSSL's EVP_PKEY_X25519.
struct X25519KeyExchange {
    private_key: PKey<openssl::pkey::Private>,
    public_key_bytes: Buf,
}

impl std::fmt::Debug for X25519KeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyExchange")
            .field("public_key_len", &self.public_key_bytes.len())
            .finish_non_exhaustive()
    }
}

impl X25519KeyExchange {
    fn new(mut buf: Buf) -> Result<Self, String> {
        let private_key =
            PKey::generate_x25519().map_err(|e| format!("X25519 key generation failed: {e}"))?;

        let raw_pub = private_key
            .raw_public_key()
            .map_err(|e| format!("X25519 public key export failed: {e}"))?;

        buf.clear();
        buf.extend_from_slice(&raw_pub);

        Ok(Self {
            private_key,
            public_key_bytes: buf,
        })
    }
}

impl ActiveKeyExchange for X25519KeyExchange {
    fn pub_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), String> {
        let peer_key = PKey::public_key_from_raw_bytes(peer_pub, openssl::pkey::Id::X25519)
            .map_err(|e| format!("Invalid X25519 peer public key: {e}"))?;

        let mut deriver =
            openssl::derive::Deriver::new(&self.private_key).map_err(|e| format!("{e}"))?;
        deriver.set_peer(&peer_key).map_err(|e| format!("{e}"))?;

        let shared_secret = deriver.derive_to_vec().map_err(|e| format!("{e}"))?;

        out.clear();
        out.extend_from_slice(&shared_secret);
        Ok(())
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

pub(super) static KX_GROUP_X25519: X25519 = X25519;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_exchange_roundtrip() {
        let alice = X25519KeyExchange::new(Buf::new()).unwrap();
        let bob = X25519KeyExchange::new(Buf::new()).unwrap();

        // Public keys should be 32 bytes
        assert_eq!(alice.pub_key().len(), 32);
        assert_eq!(bob.pub_key().len(), 32);

        let bob_pub = bob.pub_key().to_vec();
        let alice_pub = alice.pub_key().to_vec();

        let mut alice_secret = Buf::new();
        Box::new(alice)
            .complete(&bob_pub, &mut alice_secret)
            .unwrap();

        let mut bob_secret = Buf::new();
        Box::new(bob).complete(&alice_pub, &mut bob_secret).unwrap();

        // Both sides should derive the same shared secret
        assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
        assert_eq!(alice_secret.len(), 32);
    }

    #[test]
    fn invalid_peer_key_rejected() {
        let alice = X25519KeyExchange::new(Buf::new()).unwrap();
        let mut out = Buf::new();
        // Wrong length peer key
        assert!(Box::new(alice).complete(&[0u8; 16], &mut out).is_err());
    }

    /// Each X25519 key generation should produce a unique keypair.
    #[test]
    fn keys_are_unique() {
        let a = X25519KeyExchange::new(Buf::new()).unwrap();
        let b = X25519KeyExchange::new(Buf::new()).unwrap();
        assert_ne!(a.pub_key(), b.pub_key());
    }

    /// X25519 group metadata is correct.
    #[test]
    fn group_metadata() {
        let kx = X25519KeyExchange::new(Buf::new()).unwrap();
        assert_eq!(kx.group(), NamedGroup::X25519);
        assert_eq!(X25519.name(), NamedGroup::X25519);
    }

    /// The same local keypair produces different shared secrets with different peers.
    #[test]
    fn different_peers_different_secrets() {
        let alice = X25519KeyExchange::new(Buf::new()).unwrap();
        let bob = X25519KeyExchange::new(Buf::new()).unwrap();
        let carol = X25519KeyExchange::new(Buf::new()).unwrap();

        // Derive from the same local key against two different peers.
        let bob_key =
            PKey::public_key_from_raw_bytes(bob.pub_key(), openssl::pkey::Id::X25519).unwrap();
        let carol_key =
            PKey::public_key_from_raw_bytes(carol.pub_key(), openssl::pkey::Id::X25519).unwrap();

        let mut deriver_ab = openssl::derive::Deriver::new(&alice.private_key).unwrap();
        deriver_ab.set_peer(&bob_key).unwrap();
        let secret_ab = deriver_ab.derive_to_vec().unwrap();

        let mut deriver_ac = openssl::derive::Deriver::new(&alice.private_key).unwrap();
        deriver_ac.set_peer(&carol_key).unwrap();
        let secret_ac = deriver_ac.derive_to_vec().unwrap();

        // Shared secrets with different peers should differ
        assert_ne!(secret_ab.as_slice(), secret_ac.as_slice());
    }

    /// X25519 via the SupportedKxGroup trait interface.
    #[test]
    fn via_supported_kx_group_trait() {
        let group: &dyn SupportedKxGroup = &KX_GROUP_X25519;
        assert_eq!(group.name(), NamedGroup::X25519);

        let exchange = group.start_exchange(Buf::new()).unwrap();
        assert_eq!(exchange.pub_key().len(), 32);
        assert_eq!(exchange.group(), NamedGroup::X25519);
    }
}
