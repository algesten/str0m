/// Certificate fingerprint.
///
/// DTLS uses self signed certificates, and the fingerprint is communicated via
/// SDP to let the remote peer verify who is connecting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    /// Hash function used to produce the `bytes`.
    ///
    /// This is normally `sha-256`.
    pub hash_func: String,

    /// Digest of the certificate by the algorithm in `hash_func`.
    pub bytes: Vec<u8>,
}

impl ToString for Fingerprint {
    /// Convert to the hex string you find in SDP
    fn to_string(&self) -> String {
        format!(
            "{} {}",
            self.hash_func,
            self.bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":")
        )
    }
}

impl std::str::FromStr for Fingerprint {
    type Err = String;

    fn from_str(hex_string: &str) -> Result<Self, Self::Err> {
        let (hash_func, hex_with_colons) = hex_string
            .split_once(' ')
            .ok_or_else(|| "Failed to split once".to_owned())?;

        let mut bytes = Vec::new();
        for hex in hex_with_colons.split(':') {
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|e| format!("Failed to parse fingerprint: {}", e))?;
            bytes.push(byte);
        }

        Ok(Self {
            hash_func: hash_func.to_owned(),
            bytes,
        })
    }
}
