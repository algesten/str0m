//! Private, slice-checked C ABI to the locally built CryptoKit bridge.

use std::ffi::c_void;
use std::ptr::NonNull;

unsafe extern "C" {
    #[link_name = concat!(env!("STR0M_CRYPTOKIT_PREFIX"), "hash")]
    fn str0m_cryptokit_hash(size: usize, input: *const u8, count: usize, output: *mut u8);
    #[link_name = concat!(env!("STR0M_CRYPTOKIT_PREFIX"), "hmac")]
    fn str0m_cryptokit_hmac(
        size: usize,
        key: *const u8,
        key_count: usize,
        inputs: *const *const u8,
        counts: *const usize,
        count: usize,
        output: *mut u8,
    );
    #[link_name = concat!(env!("STR0M_CRYPTOKIT_PREFIX"), "hash_new")]
    fn str0m_cryptokit_hash_new(size: usize) -> *mut c_void;
    #[link_name = concat!(env!("STR0M_CRYPTOKIT_PREFIX"), "hash_update")]
    fn str0m_cryptokit_hash_update(context: *mut c_void, input: *const u8, count: usize);
    #[link_name = concat!(env!("STR0M_CRYPTOKIT_PREFIX"), "hash_snapshot")]
    fn str0m_cryptokit_hash_snapshot(context: *mut c_void, output: *mut u8);
    #[link_name = concat!(env!("STR0M_CRYPTOKIT_PREFIX"), "hash_free")]
    fn str0m_cryptokit_hash_free(context: *mut c_void);
    #[link_name = concat!(env!("STR0M_CRYPTOKIT_PREFIX"), "aes_gcm_key_new")]
    fn str0m_cryptokit_aes_gcm_key_new(key: *const u8, count: usize) -> *mut c_void;
    #[link_name = concat!(env!("STR0M_CRYPTOKIT_PREFIX"), "aes_gcm_key_free")]
    fn str0m_cryptokit_aes_gcm_key_free(context: *mut c_void);
    #[link_name = concat!(env!("STR0M_CRYPTOKIT_PREFIX"), "aes_gcm")]
    fn str0m_cryptokit_aes_gcm(
        encrypt: i32,
        context: *mut c_void,
        nonce: *const u8,
        nonce_count: usize,
        input: *const u8,
        count: usize,
        aads: *const *const u8,
        aad_counts: *const usize,
        aad_count: usize,
        output: *mut u8,
    ) -> i32;
}

fn digest<const N: usize>(data: &[u8]) -> [u8; N] {
    assert!(matches!(N, 20 | 32 | 48));
    let mut output = [0; N];
    // SAFETY: The bridge reads the borrowed input and writes exactly N digest bytes.
    unsafe { str0m_cryptokit_hash(N, data.as_ptr(), data.len(), output.as_mut_ptr()) };
    output
}

pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    digest(data)
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    digest(data)
}

pub(crate) fn sha384(data: &[u8]) -> [u8; 48] {
    digest(data)
}

// Common STUN/SRTP inputs need only a few descriptors, not a joined payload.
fn with_segments<T>(
    slices: &[&[u8]],
    call: impl FnOnce(*const *const u8, *const usize, usize) -> T,
) -> T {
    slices
        .iter()
        .try_fold(0usize, |total, slice| total.checked_add(slice.len()))
        .filter(|&total| total <= isize::MAX as usize)
        .expect("CryptoKit input length overflow");

    if slices.len() <= 4 {
        let mut pointers = [std::ptr::null(); 4];
        let mut counts = [0; 4];
        for (i, slice) in slices.iter().enumerate() {
            pointers[i] = slice.as_ptr();
            counts[i] = slice.len();
        }
        call(pointers.as_ptr(), counts.as_ptr(), slices.len())
    } else {
        let pointers: Vec<_> = slices.iter().map(|s| s.as_ptr()).collect();
        let counts: Vec<_> = slices.iter().map(|s| s.len()).collect();
        call(pointers.as_ptr(), counts.as_ptr(), slices.len())
    }
}

pub(crate) fn hmac<const N: usize>(key: &[u8], data: &[&[u8]]) -> [u8; N] {
    let mut output = [0; N];
    hmac_into::<N>(key, data, &mut output).expect("fixed-size HMAC output");
    output
}

pub(crate) fn hmac_into<const N: usize>(
    key: &[u8],
    data: &[&[u8]],
    output: &mut [u8],
) -> Result<usize, Error> {
    assert!(matches!(N, 20 | 32 | 48));
    if output.len() < N {
        return Err(Error::OutputTooSmall);
    }
    with_segments(data, |inputs, counts, count| unsafe {
        // SAFETY: All inputs and their descriptors live through the call.
        // The output has room for N authentication bytes.
        str0m_cryptokit_hmac(
            N,
            key.as_ptr(),
            key.len(),
            inputs,
            counts,
            count,
            output.as_mut_ptr(),
        );
    });
    Ok(N)
}

pub(crate) struct Hash<const N: usize>(NonNull<c_void>);

// SAFETY: Swift owns a value-type hash state with no thread affinity. Mutation requires
// &mut self; snapshot only reads/copies the state. Rust prevents concurrent writes.
unsafe impl<const N: usize> Send for Hash<N> {}
unsafe impl<const N: usize> Sync for Hash<N> {}

impl<const N: usize> Hash<N> {
    pub(crate) fn new() -> Self {
        assert!(matches!(N, 32 | 48));
        // SAFETY: Supported size; the bridge returns a retained object owned by this handle.
        let context = unsafe { str0m_cryptokit_hash_new(N) };
        Self(NonNull::new(context).expect("CryptoKit hash allocation failed"))
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        // SAFETY: The context is live and exclusively borrowed; input is valid for this call.
        unsafe { str0m_cryptokit_hash_update(self.0.as_ptr(), data.as_ptr(), data.len()) };
    }

    pub(crate) fn snapshot(&self) -> [u8; N] {
        let mut output = [0; N];
        // SAFETY: Snapshot does not mutate the context and writes exactly N bytes.
        unsafe { str0m_cryptokit_hash_snapshot(self.0.as_ptr(), output.as_mut_ptr()) };
        output
    }
}

impl<const N: usize> Drop for Hash<N> {
    fn drop(&mut self) {
        // SAFETY: This handle owns the sole retained reference and releases it exactly once.
        unsafe { str0m_cryptokit_hash_free(self.0.as_ptr()) };
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    InvalidKeyLength,
    InvalidNonceLength,
    CiphertextTooShort,
    OutputTooSmall,
    AuthenticationFailed,
    OperationFailed,
}

pub(crate) struct AesGcm(NonNull<c_void>);

// SAFETY: The retained Swift context holds an immutable SymmetricKey, with no
// thread affinity. Each operation uses its own local encryption/decryption state.
unsafe impl Send for AesGcm {}
unsafe impl Sync for AesGcm {}

impl AesGcm {
    pub(crate) fn new(key: &[u8]) -> Result<Self, Error> {
        if !matches!(key.len(), 16 | 32) {
            return Err(Error::InvalidKeyLength);
        }
        // SAFETY: Supported key size; Swift copies the key into owned secure storage.
        let context = unsafe { str0m_cryptokit_aes_gcm_key_new(key.as_ptr(), key.len()) };
        Ok(Self(
            NonNull::new(context).expect("CryptoKit AES key allocation failed"),
        ))
    }

    pub(crate) fn encrypt(
        &self,
        nonce: &[u8],
        input: &[u8],
        aad: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        // SAFETY: All slices are borrowed for the call and input/output are disjoint.
        unsafe { self.crypt(true, nonce, input, &[aad], output) }
    }

    pub(crate) fn decrypt(
        &self,
        nonce: &[u8],
        input: &[u8],
        aads: &[&[u8]],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        // SAFETY: All slices are borrowed for the call and input/output are disjoint.
        unsafe { self.crypt(false, nonce, input, aads, output) }
    }

    /// The final 16 bytes of buffer are reserved for the authentication tag.
    pub(crate) fn encrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, Error> {
        let input_len = buffer.len().checked_sub(16).ok_or(Error::OutputTooSmall)?;
        self.crypt_in_place(true, nonce, aad, input_len, buffer)
    }

    pub(crate) fn decrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, Error> {
        self.crypt_in_place(false, nonce, aad, buffer.len(), buffer)
    }

    fn crypt_in_place(
        &self,
        encrypt: bool,
        nonce: &[u8],
        aad: &[u8],
        input_len: usize,
        buffer: &mut [u8],
    ) -> Result<usize, Error> {
        let pointer = buffer.as_mut_ptr();
        let input = std::ptr::slice_from_raw_parts(pointer.cast_const(), input_len);
        let output = std::ptr::slice_from_raw_parts_mut(pointer, buffer.len());
        // SAFETY: Both pointers derive from one exclusive borrow, without creating
        // aliased Rust references. Swift consumes all input before writing output.
        unsafe { self.crypt(encrypt, nonce, input, &[aad], output) }
    }

    // Both raw slices must remain valid for the call. They may alias each other,
    // but output must not overlap nonce, AAD or the retained key context.
    unsafe fn crypt(
        &self,
        encrypt: bool,
        nonce: &[u8],
        input: *const [u8],
        aads: &[&[u8]],
        output: *mut [u8],
    ) -> Result<usize, Error> {
        if nonce.len() != 12 {
            return Err(Error::InvalidNonceLength);
        }
        let len = if encrypt {
            input.len().checked_add(16).ok_or(Error::OutputTooSmall)?
        } else {
            input
                .len()
                .checked_sub(16)
                .ok_or(Error::CiphertextTooShort)?
        };
        if output.len() < len {
            return Err(Error::OutputTooSmall);
        }
        let status = with_segments(aads, |pointers, counts, count| unsafe {
            // SAFETY: Caller guarantees valid buffers. Sizes/capacity are checked
            // above; all descriptors and borrowed AAD live through this call.
            str0m_cryptokit_aes_gcm(
                i32::from(encrypt),
                self.0.as_ptr(),
                nonce.as_ptr(),
                nonce.len(),
                input.cast(),
                input.len(),
                pointers,
                counts,
                count,
                output.cast(),
            )
        });
        match status {
            0 => Ok(len),
            2 => Err(Error::AuthenticationFailed),
            _ => Err(Error::OperationFailed),
        }
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        // SAFETY: This handle owns the retained context and releases it exactly once.
        unsafe { str0m_cryptokit_aes_gcm_key_free(self.0.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha384_vectors() {
        assert_eq!(
            hex(&sha384(b"")),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            hex(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn hmac_rfc4231() {
        let key = [0x0b; 20];
        assert_eq!(
            hex(&hmac::<32>(&key, &[b"Hi There"])),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac::<48>(&key, &[b"Hi There"])),
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
        );
        assert_eq!(
            hex(&hmac::<32>(b"", &[])),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
    }

    #[test]
    fn hmac_writes_only_the_digest_and_checks_output_capacity() {
        fn check<const N: usize>() {
            let mut output = vec![0xa5; N + 3];
            for size in 0..N {
                assert_eq!(
                    hmac_into::<N>(b"key", &[b"data"], &mut output[..size]),
                    Err(Error::OutputTooSmall)
                );
                assert!(output.iter().all(|&b| b == 0xa5));
            }
            assert_eq!(hmac_into::<N>(b"key", &[b"data"], &mut output), Ok(N));
            assert_eq!(&output[..N], &hmac::<N>(b"key", &[b"data"]));
            assert_eq!(&output[N..], &[0xa5; 3]);
        }
        check::<20>();
        check::<32>();
        check::<48>();
    }

    fn check_snapshots<const N: usize>() {
        let mut hash = Hash::<N>::new();
        assert_eq!(hash.snapshot(), digest::<N>(b""));
        hash.update(b"");
        hash.update(b"a");
        hash.update(b"b");
        assert_eq!(hash.snapshot(), digest::<N>(b"ab"));
        assert_eq!(hash.snapshot(), digest::<N>(b"ab"));
        hash.update(b"c");
        assert_eq!(hash.snapshot(), digest::<N>(b"abc"));

        std::thread::scope(|scope| {
            for _ in 0..4 {
                let hash = &hash;
                scope.spawn(move || assert_eq!(hash.snapshot(), digest::<N>(b"abc")));
            }
        });
        std::thread::spawn(move || {
            hash.update(b"d");
            assert_eq!(hash.snapshot(), digest::<N>(b"abcd"));
        })
        .join()
        .unwrap();
    }

    #[test]
    fn incremental_hash_snapshots_and_cross_thread_ownership() {
        check_snapshots::<32>();
        check_snapshots::<48>();
    }

    #[test]
    fn aes_gcm_empty_plaintext() {
        for key in [&[0; 16][..], &[0; 32][..]] {
            let cipher = AesGcm::new(key).unwrap();
            let mut ciphertext = [0; 17];
            assert_eq!(cipher.encrypt(&[0; 12], b"", b"", &mut ciphertext), Ok(16));
            assert_eq!(ciphertext[16], 0);
            assert_eq!(
                cipher.decrypt(&[0; 12], &ciphertext[..16], &[], &mut []),
                Ok(0)
            );
        }
    }

    #[test]
    fn aes_gcm_rejects_invalid_buffers_without_writing() {
        for size in [0, 15, 17, 24, 31, 33] {
            assert!(matches!(
                AesGcm::new(&vec![0; size]),
                Err(Error::InvalidKeyLength)
            ));
        }
        let cipher = AesGcm::new(&[0; 16]).unwrap();
        let mut output = [0xa5; 32];
        assert_eq!(
            cipher.encrypt(&[0; 11], &[0; 16], b"", &mut output),
            Err(Error::InvalidNonceLength)
        );
        assert_eq!(
            cipher.decrypt(&[0; 11], &[0; 16], &[], &mut output),
            Err(Error::InvalidNonceLength)
        );
        assert_eq!(
            cipher.encrypt(&[0; 12], b"x", b"", &mut output[..16]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(
            cipher.decrypt(&[0; 12], &[0; 17], &[], &mut []),
            Err(Error::OutputTooSmall)
        );
        for len in 0..16 {
            assert_eq!(
                cipher.decrypt(&[0; 12], &[0; 16][..len], &[], &mut output),
                Err(Error::CiphertextTooShort)
            );
        }
        assert_eq!(output, [0xa5; 32]);
    }

    #[test]
    fn aes_gcm_authenticates_all_inputs_before_writing() {
        for key in [&[0; 16][..], &[0; 32][..]] {
            let cipher = AesGcm::new(key).unwrap();
            let mut ciphertext = [0; 21];
            cipher
                .encrypt(&[0; 12], b"hello", b"aad", &mut ciphertext)
                .unwrap();
            let mut output = [0xa5; 6];
            assert_eq!(
                cipher.decrypt(&[0; 12], &ciphertext, &[b"aad"], &mut output),
                Ok(5)
            );
            assert_eq!(&output, b"hello\xa5");
            let wrong_key = AesGcm::new(&vec![1; key.len()]).unwrap();
            let mut output = [0xa5; 5];
            assert_eq!(
                wrong_key.decrypt(&[0; 12], &ciphertext, &[b"aad"], &mut output),
                Err(Error::AuthenticationFailed)
            );
            assert_eq!(output, [0xa5; 5]);
            for index in 0..ciphertext.len() {
                let mut tampered = ciphertext;
                tampered[index] ^= 1;
                let mut output = [0xa5; 5];
                assert_eq!(
                    cipher.decrypt(&[0; 12], &tampered, &[b"aad"], &mut output),
                    Err(Error::AuthenticationFailed)
                );
                assert_eq!(output, [0xa5; 5]);
            }
            for (nonce, aad) in [([1; 12], &b"aad"[..]), ([0; 12], &b"bad"[..])] {
                let mut output = [0xa5; 5];
                assert_eq!(
                    cipher.decrypt(&nonce, &ciphertext, &[aad], &mut output),
                    Err(Error::AuthenticationFailed)
                );
                assert_eq!(output, [0xa5; 5]);
            }
        }
    }

    #[test]
    fn fragmented_inputs_match_contiguous_inputs() {
        for parts in [
            &[][..],
            &[&b""[..]][..],
            &[&b"Hi "[..], &b""[..], &b"There"[..]][..],
            &[
                &b""[..],
                &b"H"[..],
                &b"i "[..],
                &b""[..],
                &b"T"[..],
                &b"here"[..],
            ][..],
        ] {
            let joined = parts.concat();
            assert_eq!(hmac::<20>(b"key", parts), hmac::<20>(b"key", &[&joined]));
            assert_eq!(hmac::<32>(b"key", parts), hmac::<32>(b"key", &[&joined]));
            assert_eq!(hmac::<48>(b"key", parts), hmac::<48>(b"key", &[&joined]));
            for key in [&[0; 16][..], &[0; 32][..]] {
                let cipher = AesGcm::new(key).unwrap();
                let mut ciphertext = [0; 21];
                cipher
                    .encrypt(&[0; 12], b"hello", &joined, &mut ciphertext)
                    .unwrap();
                let mut plaintext = [0; 5];
                assert_eq!(
                    cipher.decrypt(&[0; 12], &ciphertext, parts, &mut plaintext),
                    Ok(5)
                );
                assert_eq!(&plaintext, b"hello");
            }
        }
    }

    #[test]
    fn in_place_aes_gcm_preserves_buffers_on_failure() {
        for key in [&[0; 16][..], &[0; 32][..]] {
            let cipher = AesGcm::new(key).unwrap();
            for size in [0, 1, 16, 1023, 1024, 1200, 65535] {
                let mut buffer = vec![0xab; size + 16];
                let pointer = buffer.as_ptr();
                let mut expected = vec![0; buffer.len()];
                cipher
                    .encrypt(&[0; 12], &buffer[..size], b"aad", &mut expected)
                    .unwrap();
                assert_eq!(
                    cipher.encrypt_in_place(&[0; 12], b"aad", &mut buffer),
                    Ok(size + 16)
                );
                assert_eq!(buffer, expected);
                assert_eq!(buffer.as_ptr(), pointer);

                assert_eq!(
                    cipher.decrypt_in_place(&[0; 11], b"aad", &mut buffer),
                    Err(Error::InvalidNonceLength)
                );
                assert_eq!(buffer, expected);
                assert_eq!(
                    cipher.decrypt_in_place(&[0; 12], b"bad", &mut buffer),
                    Err(Error::AuthenticationFailed)
                );
                assert_eq!(buffer, expected);
                assert_eq!(
                    cipher.encrypt_in_place(&[0; 11], b"aad", &mut buffer),
                    Err(Error::InvalidNonceLength)
                );
                assert_eq!(buffer, expected);

                assert_eq!(
                    cipher.decrypt_in_place(&[0; 12], b"aad", &mut buffer),
                    Ok(size)
                );
                assert_eq!(&buffer[..size], &vec![0xab; size]);
                assert_eq!(buffer.as_ptr(), pointer);
            }
            for size in 0..16 {
                let mut buffer = [0xa5; 16];
                assert_eq!(
                    cipher.decrypt_in_place(&[0; 12], b"", &mut buffer[..size]),
                    Err(Error::CiphertextTooShort)
                );
                assert_eq!(
                    cipher.encrypt_in_place(&[0; 12], b"", &mut buffer[..size]),
                    Err(Error::OutputTooSmall)
                );
                assert_eq!(buffer, [0xa5; 16]);
            }
        }
    }

    #[test]
    fn aes_key_owns_its_bytes_and_can_move_between_threads() {
        let mut bytes = [0; 16];
        let cipher = AesGcm::new(&bytes).unwrap();
        let mut expected = [0; 16];
        cipher.encrypt(&[0; 12], b"", b"", &mut expected).unwrap();
        bytes.fill(1);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let cipher = &cipher;
                scope.spawn(move || {
                    let mut output = [0; 16];
                    cipher.encrypt(&[0; 12], b"", b"", &mut output).unwrap();
                    assert_eq!(output, expected);
                });
            }
        });
        std::thread::spawn(move || {
            assert_eq!(cipher.decrypt(&[0; 12], &expected, &[], &mut []), Ok(0));
        })
        .join()
        .unwrap();
    }
}
