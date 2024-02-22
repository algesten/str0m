use core::fmt;

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

// DO NOT CHANGE!
// This format is exactly what's needed in n SDP.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.hash_func)?;
        for (i, b) in self.bytes.iter().enumerate() {
            if i > 0 {
                write!(f, ":")?;
            }
            write!(f, "{:02X}", b)?;
        }
        Ok(())
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
