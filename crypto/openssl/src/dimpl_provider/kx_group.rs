//! Key exchange group implementations using OpenSSL.

use dimpl::crypto::Buf;
use dimpl::crypto::{ActiveKeyExchange, NamedGroup, SupportedKxGroup};

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::PKey;

/// Map a `NamedGroup` to the corresponding OpenSSL `Nid`.
fn nid_for_group(group: NamedGroup) -> Result<Nid, String> {
    match group {
        NamedGroup::Secp256r1 => Ok(Nid::X9_62_PRIME256V1),
        NamedGroup::Secp384r1 => Ok(Nid::SECP384R1),
        _ => Err(format!("Unsupported group: {group:?}")),
    }
}

/// ECDHE key exchange implementation using OpenSSL.
struct EcdhKeyExchange {
    private_key: EcKey<openssl::pkey::Private>,
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
        let nid = nid_for_group(group)?;

        let ec_group = EcGroup::from_curve_name(nid).map_err(|e| format!("{e}"))?;
        let ec_key = EcKey::generate(&ec_group).map_err(|e| format!("{e}"))?;

        // Export public key as SEC1 uncompressed point format
        let mut ctx = BigNumContext::new().map_err(|e| format!("{e}"))?;
        let public_key_bytes = ec_key
            .public_key()
            .to_bytes(&ec_group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(|e| format!("{e}"))?;

        buf.clear();
        buf.extend_from_slice(&public_key_bytes);

        Ok(Self {
            private_key: ec_key,
            public_key_bytes: buf,
            group,
        })
    }
}

impl ActiveKeyExchange for EcdhKeyExchange {
    fn pub_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), String> {
        let nid = nid_for_group(self.group)?;

        let ec_group = EcGroup::from_curve_name(nid).map_err(|e| format!("{e}"))?;
        let mut ctx = BigNumContext::new().map_err(|e| format!("{e}"))?;

        // Import peer's public key
        let peer_point =
            EcPoint::from_bytes(&ec_group, peer_pub, &mut ctx).map_err(|e| format!("{e}"))?;

        // Perform ECDH key agreement
        let pkey = PKey::from_ec_key(self.private_key).map_err(|e| format!("{e}"))?;
        let peer_ec_key =
            EcKey::from_public_key(&ec_group, &peer_point).map_err(|e| format!("{e}"))?;
        let peer_pkey = PKey::from_ec_key(peer_ec_key).map_err(|e| format!("{e}"))?;

        let mut deriver = openssl::derive::Deriver::new(&pkey).map_err(|e| format!("{e}"))?;
        deriver.set_peer(&peer_pkey).map_err(|e| format!("{e}"))?;

        let shared_secret = deriver.derive_to_vec().map_err(|e| format!("{e}"))?;

        out.clear();
        out.extend_from_slice(&shared_secret);
        Ok(())
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

/// P-256 (secp256r1) key exchange group.
#[derive(Debug)]
struct P256;

impl SupportedKxGroup for P256 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp256r1
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp256r1, buf)?))
    }
}

/// P-384 (secp384r1) key exchange group.
#[derive(Debug)]
struct P384;

impl SupportedKxGroup for P384 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp384r1
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp384r1, buf)?))
    }
}

static KX_GROUP_P256: P256 = P256;
static KX_GROUP_P384: P384 = P384;

#[cfg(not(feature = "fips140"))]
pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &KX_GROUP_P256,
    &KX_GROUP_P384,
    &super::x25519::KX_GROUP_X25519,
];
#[cfg(feature = "fips140")]
pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&KX_GROUP_P256, &KX_GROUP_P384];

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ECDH (P-256 / P-384) tests
    // ========================================================================

    #[test]
    fn p256_key_exchange_roundtrip() {
        let alice = EcdhKeyExchange::new(NamedGroup::Secp256r1, Buf::new()).unwrap();
        let bob = EcdhKeyExchange::new(NamedGroup::Secp256r1, Buf::new()).unwrap();

        // P-256 uncompressed point: 1 + 32 + 32 = 65 bytes
        assert_eq!(alice.pub_key().len(), 65);
        assert_eq!(bob.pub_key().len(), 65);
        assert_eq!(alice.group(), NamedGroup::Secp256r1);

        let bob_pub = bob.pub_key().to_vec();
        let alice_pub = alice.pub_key().to_vec();

        let mut alice_secret = Buf::new();
        Box::new(alice)
            .complete(&bob_pub, &mut alice_secret)
            .unwrap();

        let mut bob_secret = Buf::new();
        Box::new(bob).complete(&alice_pub, &mut bob_secret).unwrap();

        assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
        assert_eq!(alice_secret.len(), 32); // P-256 shared secret is 32 bytes
    }

    #[test]
    fn p384_key_exchange_roundtrip() {
        let alice = EcdhKeyExchange::new(NamedGroup::Secp384r1, Buf::new()).unwrap();
        let bob = EcdhKeyExchange::new(NamedGroup::Secp384r1, Buf::new()).unwrap();

        // P-384 uncompressed point: 1 + 48 + 48 = 97 bytes
        assert_eq!(alice.pub_key().len(), 97);
        assert_eq!(bob.pub_key().len(), 97);
        assert_eq!(alice.group(), NamedGroup::Secp384r1);

        let bob_pub = bob.pub_key().to_vec();
        let alice_pub = alice.pub_key().to_vec();

        let mut alice_secret = Buf::new();
        Box::new(alice)
            .complete(&bob_pub, &mut alice_secret)
            .unwrap();

        let mut bob_secret = Buf::new();
        Box::new(bob).complete(&alice_pub, &mut bob_secret).unwrap();

        assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
        assert_eq!(alice_secret.len(), 48); // P-384 shared secret is 48 bytes
    }

    #[test]
    fn p256_keys_are_unique() {
        let a = EcdhKeyExchange::new(NamedGroup::Secp256r1, Buf::new()).unwrap();
        let b = EcdhKeyExchange::new(NamedGroup::Secp256r1, Buf::new()).unwrap();
        assert_ne!(a.pub_key(), b.pub_key());
    }

    #[test]
    fn p256_invalid_peer_key_rejected() {
        let alice = EcdhKeyExchange::new(NamedGroup::Secp256r1, Buf::new()).unwrap();
        let mut out = Buf::new();
        // Garbage peer key
        assert!(Box::new(alice).complete(&[0xffu8; 65], &mut out).is_err());
    }

    #[test]
    fn p384_invalid_peer_key_rejected() {
        let alice = EcdhKeyExchange::new(NamedGroup::Secp384r1, Buf::new()).unwrap();
        let mut out = Buf::new();
        assert!(Box::new(alice).complete(&[0xffu8; 97], &mut out).is_err());
    }

    /// Cross-group exchange should fail (P-256 key to P-384 peer).
    #[test]
    fn cross_group_exchange_fails() {
        let alice = EcdhKeyExchange::new(NamedGroup::Secp256r1, Buf::new()).unwrap();
        let bob = EcdhKeyExchange::new(NamedGroup::Secp384r1, Buf::new()).unwrap();

        let bob_pub = bob.pub_key().to_vec();
        let mut out = Buf::new();
        // P-384 public key is 97 bytes, not a valid P-256 point
        assert!(Box::new(alice).complete(&bob_pub, &mut out).is_err());
    }

    /// Verify all groups in ALL_KX_GROUPS are distinct.
    #[test]
    fn all_kx_groups_unique() {
        let names: Vec<_> = ALL_KX_GROUPS.iter().map(|g| g.name()).collect();
        for (i, a) in names.iter().enumerate() {
            for b in &names[i + 1..] {
                assert_ne!(a, b, "duplicate key exchange group");
            }
        }
    }

    /// ALL_KX_GROUPS contains the expected groups.
    #[test]
    fn all_kx_groups_contains_expected() {
        let names: Vec<_> = ALL_KX_GROUPS.iter().map(|g| g.name()).collect();
        assert!(names.contains(&NamedGroup::Secp256r1));
        assert!(names.contains(&NamedGroup::Secp384r1));
        #[cfg(not(feature = "fips140"))]
        assert!(names.contains(&NamedGroup::X25519));
    }

    /// SupportedKxGroup trait produces working exchanges for all groups.
    #[test]
    fn all_kx_groups_produce_working_exchanges() {
        for group in ALL_KX_GROUPS {
            let alice = group.start_exchange(Buf::new()).unwrap();
            let bob = group.start_exchange(Buf::new()).unwrap();

            let bob_pub = bob.pub_key().to_vec();
            let alice_pub = alice.pub_key().to_vec();

            let mut alice_secret = Buf::new();
            alice.complete(&bob_pub, &mut alice_secret).unwrap();

            let mut bob_secret = Buf::new();
            bob.complete(&alice_pub, &mut bob_secret).unwrap();

            assert_eq!(
                alice_secret.as_ref(),
                bob_secret.as_ref(),
                "shared secret mismatch for {:?}",
                group.name()
            );
            assert!(!alice_secret.is_empty());
        }
    }
}
