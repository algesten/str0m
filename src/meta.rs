/// Marker trait for customising the buffer types used by [`Rtc`][crate::Rtc].
///
/// This trait has one associated type, [`Meta::Input`], which controls what
/// type is accepted by [`Writer::write`][crate::media::Writer::write].
///
/// The default implementation is [`DefaultMeta`], which uses `Vec<u8>`.
pub trait Meta {
    /// The buffer type accepted by [`Writer::write`][crate::media::Writer::write].
    ///
    /// Must implement [`AsRef<[u8]>`] so the str0m can read the payload bytes
    /// for packetisation and [`Into<Vec<u8>>`] for internal conversions.
    type Input: AsRef<[u8]> + Into<Vec<u8>>;
}

/// Default [`Meta`] implementation using `Vec<u8>` as the input buffer.
pub struct DefaultMeta;

impl Meta for DefaultMeta {
    type Input = Vec<u8>;
}
