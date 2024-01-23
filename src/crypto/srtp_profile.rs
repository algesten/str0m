use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpProfile {
    #[cfg(feature = "_internal_test_exports")]
    PassThrough,
    Aes128CmSha1_80,
    AeadAes128Gcm,
}

impl fmt::Display for SrtpProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "_internal_test_exports")]
            SrtpProfile::PassThrough => write!(f, "PassThrough"),
            SrtpProfile::Aes128CmSha1_80 => write!(f, "SRTP_AES128_CM_SHA1_80"),
            SrtpProfile::AeadAes128Gcm => write!(f, "SRTP_AEAD_AES_128_GCM"),
        }
    }
}
