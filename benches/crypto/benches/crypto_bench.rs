//! Crypto Provider Comparison Benchmarks
//!
//! This benchmark compares the cryptographic performance of:
//! - OpenSSL
//! - AWS-LC-RS
//! - RustCrypto
//! - Apple CommonCrypto (macOS only)
//! - WinCrypto (Windows only)
//!
//! Run with: cargo bench --release -- --verbose
//! Or for native optimizations: RUSTFLAGS="-C target-cpu=native" cargo bench --release

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use str0m_proto::crypto::CryptoProvider;

// Test data sizes for throughput testing
const SMALL_DATA_SIZE: usize = 172; // Typical RTP packet payload
const MEDIUM_DATA_SIZE: usize = 512; // Medium payload
const LARGE_DATA_SIZE: usize = 1200; // MTU-sized payload

fn get_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i & 0xFF) as u8).collect()
}

// ============================================================================
// Provider Initialization
// ============================================================================

fn openssl_provider() -> CryptoProvider {
    str0m_openssl::default_provider()
}

fn aws_lc_rs_provider() -> CryptoProvider {
    str0m_aws_lc_rs::default_provider()
}

fn rust_crypto_provider() -> CryptoProvider {
    str0m_rust_crypto::default_provider()
}

#[cfg(target_vendor = "apple")]
fn apple_crypto_provider() -> CryptoProvider {
    str0m_apple_crypto::default_provider()
}

#[cfg(windows)]
fn wincrypto_provider() -> CryptoProvider {
    str0m_wincrypto::default_provider()
}

// ============================================================================
// SHA-256 Benchmarks
// ============================================================================

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA256");

    for size in [SMALL_DATA_SIZE, MEDIUM_DATA_SIZE, LARGE_DATA_SIZE] {
        let data = get_test_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("OpenSSL", size), &data, |b, data| {
            let provider = openssl_provider();
            b.iter(|| provider.sha256_provider.sha256(black_box(data)))
        });

        group.bench_with_input(BenchmarkId::new("AWS-LC-RS", size), &data, |b, data| {
            let provider = aws_lc_rs_provider();
            b.iter(|| provider.sha256_provider.sha256(black_box(data)))
        });

        group.bench_with_input(BenchmarkId::new("RustCrypto", size), &data, |b, data| {
            let provider = rust_crypto_provider();
            b.iter(|| provider.sha256_provider.sha256(black_box(data)))
        });

        #[cfg(target_vendor = "apple")]
        group.bench_with_input(BenchmarkId::new("AppleCrypto", size), &data, |b, data| {
            let provider = apple_crypto_provider();
            b.iter(|| provider.sha256_provider.sha256(black_box(data)))
        });

        #[cfg(windows)]
        group.bench_with_input(BenchmarkId::new("WinCrypto", size), &data, |b, data| {
            let provider = wincrypto_provider();
            b.iter(|| provider.sha256_provider.sha256(black_box(data)))
        });
    }

    group.finish();
}

// ============================================================================
// SHA1-HMAC Benchmarks
// ============================================================================

fn bench_sha1_hmac(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA1-HMAC");

    let key = [0x42u8; 20]; // HMAC key

    for size in [SMALL_DATA_SIZE, MEDIUM_DATA_SIZE, LARGE_DATA_SIZE] {
        let data = get_test_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("OpenSSL", size), &data, |b, data| {
            let provider = openssl_provider();
            b.iter(|| {
                provider
                    .sha1_hmac_provider
                    .sha1_hmac(black_box(&key), black_box(&[data.as_slice()]))
            })
        });

        group.bench_with_input(BenchmarkId::new("AWS-LC-RS", size), &data, |b, data| {
            let provider = aws_lc_rs_provider();
            b.iter(|| {
                provider
                    .sha1_hmac_provider
                    .sha1_hmac(black_box(&key), black_box(&[data.as_slice()]))
            })
        });

        group.bench_with_input(BenchmarkId::new("RustCrypto", size), &data, |b, data| {
            let provider = rust_crypto_provider();
            b.iter(|| {
                provider
                    .sha1_hmac_provider
                    .sha1_hmac(black_box(&key), black_box(&[data.as_slice()]))
            })
        });

        #[cfg(target_vendor = "apple")]
        group.bench_with_input(BenchmarkId::new("AppleCrypto", size), &data, |b, data| {
            let provider = apple_crypto_provider();
            b.iter(|| {
                provider
                    .sha1_hmac_provider
                    .sha1_hmac(black_box(&key), black_box(&[data.as_slice()]))
            })
        });

        #[cfg(windows)]
        group.bench_with_input(BenchmarkId::new("WinCrypto", size), &data, |b, data| {
            let provider = wincrypto_provider();
            b.iter(|| {
                provider
                    .sha1_hmac_provider
                    .sha1_hmac(black_box(&key), black_box(&[data.as_slice()]))
            })
        });
    }

    group.finish();
}

// ============================================================================
// AES-128-ECB Round (Key Derivation) Benchmarks
// ============================================================================

fn bench_aes_128_ecb_round(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-128-ECB-Round");

    let key = [0x42u8; 16];
    let input = [0x00u8; 16];
    // OpenSSL requires 32 bytes output buffer for ECB round
    let mut output = [0u8; 32];

    group.bench_function("OpenSSL", |b| {
        let provider = openssl_provider();
        b.iter(|| {
            provider.srtp_provider.srtp_aes_128_ecb_round(
                black_box(&key),
                black_box(&input),
                black_box(&mut output),
            )
        })
    });

    group.bench_function("AWS-LC-RS", |b| {
        let provider = aws_lc_rs_provider();
        b.iter(|| {
            provider.srtp_provider.srtp_aes_128_ecb_round(
                black_box(&key),
                black_box(&input),
                black_box(&mut output),
            )
        })
    });

    group.bench_function("RustCrypto", |b| {
        let provider = rust_crypto_provider();
        b.iter(|| {
            provider.srtp_provider.srtp_aes_128_ecb_round(
                black_box(&key),
                black_box(&input),
                black_box(&mut output),
            )
        })
    });

    #[cfg(target_vendor = "apple")]
    group.bench_function("AppleCrypto", |b| {
        let provider = apple_crypto_provider();
        b.iter(|| {
            provider.srtp_provider.srtp_aes_128_ecb_round(
                black_box(&key),
                black_box(&input),
                black_box(&mut output),
            )
        })
    });

    #[cfg(windows)]
    group.bench_function("WinCrypto", |b| {
        let provider = wincrypto_provider();
        b.iter(|| {
            provider.srtp_provider.srtp_aes_128_ecb_round(
                black_box(&key),
                black_box(&input),
                black_box(&mut output),
            )
        })
    });

    group.finish();
}

// ============================================================================
// AES-256-ECB Round (Key Derivation) Benchmarks
// ============================================================================

fn bench_aes_256_ecb_round(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-ECB-Round");

    let key = [0x42u8; 32];
    let input = [0x00u8; 16];
    // OpenSSL requires 32 bytes output buffer for ECB round
    let mut output = [0u8; 32];

    group.bench_function("OpenSSL", |b| {
        let provider = openssl_provider();
        b.iter(|| {
            provider.srtp_provider.srtp_aes_256_ecb_round(
                black_box(&key),
                black_box(&input),
                black_box(&mut output),
            )
        })
    });

    group.bench_function("AWS-LC-RS", |b| {
        let provider = aws_lc_rs_provider();
        b.iter(|| {
            provider.srtp_provider.srtp_aes_256_ecb_round(
                black_box(&key),
                black_box(&input),
                black_box(&mut output),
            )
        })
    });

    group.bench_function("RustCrypto", |b| {
        let provider = rust_crypto_provider();
        b.iter(|| {
            provider.srtp_provider.srtp_aes_256_ecb_round(
                black_box(&key),
                black_box(&input),
                black_box(&mut output),
            )
        })
    });

    #[cfg(target_vendor = "apple")]
    group.bench_function("AppleCrypto", |b| {
        let provider = apple_crypto_provider();
        b.iter(|| {
            provider.srtp_provider.srtp_aes_256_ecb_round(
                black_box(&key),
                black_box(&input),
                black_box(&mut output),
            )
        })
    });

    #[cfg(windows)]
    group.bench_function("WinCrypto", |b| {
        let provider = wincrypto_provider();
        b.iter(|| {
            provider.srtp_provider.srtp_aes_256_ecb_round(
                black_box(&key),
                black_box(&input),
                black_box(&mut output),
            )
        })
    });

    group.finish();
}

// ============================================================================
// AES-128-CM-SHA1-80 (SRTP) Encrypt Benchmarks
// ============================================================================

fn bench_aes_128_cm_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-128-CM-SHA1-80-Encrypt");

    let key: [u8; 16] = [0x42u8; 16];
    let iv: [u8; 16] = [0x00u8; 16];

    for size in [SMALL_DATA_SIZE, MEDIUM_DATA_SIZE, LARGE_DATA_SIZE] {
        let input = get_test_data(size);
        let mut output = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("OpenSSL", size), &input, |b, input| {
            let provider = openssl_provider();
            let mut cipher = provider.srtp_provider.aes_128_cm_sha1_80().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(black_box(&iv), black_box(input), black_box(&mut output))
                    .unwrap()
            })
        });

        group.bench_with_input(BenchmarkId::new("AWS-LC-RS", size), &input, |b, input| {
            let provider = aws_lc_rs_provider();
            let mut cipher = provider.srtp_provider.aes_128_cm_sha1_80().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(black_box(&iv), black_box(input), black_box(&mut output))
                    .unwrap()
            })
        });

        group.bench_with_input(BenchmarkId::new("RustCrypto", size), &input, |b, input| {
            let provider = rust_crypto_provider();
            let mut cipher = provider.srtp_provider.aes_128_cm_sha1_80().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(black_box(&iv), black_box(input), black_box(&mut output))
                    .unwrap()
            })
        });

        #[cfg(target_vendor = "apple")]
        group.bench_with_input(BenchmarkId::new("AppleCrypto", size), &input, |b, input| {
            let provider = apple_crypto_provider();
            let mut cipher = provider.srtp_provider.aes_128_cm_sha1_80().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(black_box(&iv), black_box(input), black_box(&mut output))
                    .unwrap()
            })
        });

        #[cfg(windows)]
        group.bench_with_input(BenchmarkId::new("WinCrypto", size), &input, |b, input| {
            let provider = wincrypto_provider();
            let mut cipher = provider.srtp_provider.aes_128_cm_sha1_80().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(black_box(&iv), black_box(input), black_box(&mut output))
                    .unwrap()
            })
        });
    }

    group.finish();
}

// ============================================================================
// AES-128-GCM (SRTP AEAD) Encrypt Benchmarks
// ============================================================================

fn bench_aes_128_gcm_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("AEAD-AES-128-GCM-Encrypt");

    let key: [u8; 16] = [0x42u8; 16];
    let iv: [u8; 12] = [0x00u8; 12];
    let aad: [u8; 12] = [0x01u8; 12]; // Minimum 12 bytes AAD

    for size in [SMALL_DATA_SIZE, MEDIUM_DATA_SIZE, LARGE_DATA_SIZE] {
        let input = get_test_data(size);
        let mut output = vec![0u8; size + 16]; // Extra space for GCM tag
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("OpenSSL", size), &input, |b, input| {
            let provider = openssl_provider();
            let mut cipher = provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(
                        black_box(&iv),
                        black_box(&aad),
                        black_box(input),
                        black_box(&mut output),
                    )
                    .unwrap()
            })
        });

        group.bench_with_input(BenchmarkId::new("AWS-LC-RS", size), &input, |b, input| {
            let provider = aws_lc_rs_provider();
            let mut cipher = provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(
                        black_box(&iv),
                        black_box(&aad),
                        black_box(input),
                        black_box(&mut output),
                    )
                    .unwrap()
            })
        });

        group.bench_with_input(BenchmarkId::new("RustCrypto", size), &input, |b, input| {
            let provider = rust_crypto_provider();
            let mut cipher = provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(
                        black_box(&iv),
                        black_box(&aad),
                        black_box(input),
                        black_box(&mut output),
                    )
                    .unwrap()
            })
        });

        #[cfg(target_vendor = "apple")]
        group.bench_with_input(BenchmarkId::new("AppleCrypto", size), &input, |b, input| {
            let provider = apple_crypto_provider();
            let mut cipher = provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(
                        black_box(&iv),
                        black_box(&aad),
                        black_box(input),
                        black_box(&mut output),
                    )
                    .unwrap()
            })
        });

        #[cfg(windows)]
        group.bench_with_input(BenchmarkId::new("WinCrypto", size), &input, |b, input| {
            let provider = wincrypto_provider();
            let mut cipher = provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(
                        black_box(&iv),
                        black_box(&aad),
                        black_box(input),
                        black_box(&mut output),
                    )
                    .unwrap()
            })
        });
    }

    group.finish();
}

// ============================================================================
// AES-256-GCM (SRTP AEAD) Encrypt Benchmarks
// ============================================================================

fn bench_aes_256_gcm_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("AEAD-AES-256-GCM-Encrypt");

    let key: [u8; 32] = [0x42u8; 32];
    let iv: [u8; 12] = [0x00u8; 12];
    let aad: [u8; 12] = [0x01u8; 12]; // Minimum 12 bytes AAD

    for size in [SMALL_DATA_SIZE, MEDIUM_DATA_SIZE, LARGE_DATA_SIZE] {
        let input = get_test_data(size);
        let mut output = vec![0u8; size + 16]; // Extra space for GCM tag
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("OpenSSL", size), &input, |b, input| {
            let provider = openssl_provider();
            let mut cipher = provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(
                        black_box(&iv),
                        black_box(&aad),
                        black_box(input),
                        black_box(&mut output),
                    )
                    .unwrap()
            })
        });

        group.bench_with_input(BenchmarkId::new("AWS-LC-RS", size), &input, |b, input| {
            let provider = aws_lc_rs_provider();
            let mut cipher = provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(
                        black_box(&iv),
                        black_box(&aad),
                        black_box(input),
                        black_box(&mut output),
                    )
                    .unwrap()
            })
        });

        group.bench_with_input(BenchmarkId::new("RustCrypto", size), &input, |b, input| {
            let provider = rust_crypto_provider();
            let mut cipher = provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(
                        black_box(&iv),
                        black_box(&aad),
                        black_box(input),
                        black_box(&mut output),
                    )
                    .unwrap()
            })
        });

        #[cfg(target_vendor = "apple")]
        group.bench_with_input(BenchmarkId::new("AppleCrypto", size), &input, |b, input| {
            let provider = apple_crypto_provider();
            let mut cipher = provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(
                        black_box(&iv),
                        black_box(&aad),
                        black_box(input),
                        black_box(&mut output),
                    )
                    .unwrap()
            })
        });

        #[cfg(windows)]
        group.bench_with_input(BenchmarkId::new("WinCrypto", size), &input, |b, input| {
            let provider = wincrypto_provider();
            let mut cipher = provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, true);
            b.iter(|| {
                cipher
                    .encrypt(
                        black_box(&iv),
                        black_box(&aad),
                        black_box(input),
                        black_box(&mut output),
                    )
                    .unwrap()
            })
        });
    }

    group.finish();
}

// ============================================================================
// AES-128-GCM (SRTP AEAD) Decrypt Benchmarks
// ============================================================================

fn bench_aes_128_gcm_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("AEAD-AES-128-GCM-Decrypt");

    let key: [u8; 16] = [0x42u8; 16];
    let iv: [u8; 12] = [0x00u8; 12];
    let aad: [u8; 12] = [0x01u8; 12];

    for size in [SMALL_DATA_SIZE, MEDIUM_DATA_SIZE, LARGE_DATA_SIZE] {
        // First encrypt to get valid ciphertext
        let input = get_test_data(size);
        let mut encrypted = vec![0u8; size + 16];

        let provider = openssl_provider();
        let mut cipher = provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, true);
        cipher.encrypt(&iv, &aad, &input, &mut encrypted).unwrap();

        let mut output = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("OpenSSL", size),
            &encrypted,
            |b, encrypted| {
                let provider = openssl_provider();
                let mut cipher =
                    provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, false);
                b.iter(|| {
                    cipher
                        .decrypt(
                            black_box(&iv),
                            black_box(&[aad.as_slice()]),
                            black_box(encrypted),
                            black_box(&mut output),
                        )
                        .unwrap()
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("AWS-LC-RS", size),
            &encrypted,
            |b, encrypted| {
                let provider = aws_lc_rs_provider();
                let mut cipher =
                    provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, false);
                b.iter(|| {
                    cipher
                        .decrypt(
                            black_box(&iv),
                            black_box(&[aad.as_slice()]),
                            black_box(encrypted),
                            black_box(&mut output),
                        )
                        .unwrap()
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("RustCrypto", size),
            &encrypted,
            |b, encrypted| {
                let provider = rust_crypto_provider();
                let mut cipher =
                    provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, false);
                b.iter(|| {
                    cipher
                        .decrypt(
                            black_box(&iv),
                            black_box(&[aad.as_slice()]),
                            black_box(encrypted),
                            black_box(&mut output),
                        )
                        .unwrap()
                })
            },
        );

        #[cfg(target_vendor = "apple")]
        group.bench_with_input(
            BenchmarkId::new("AppleCrypto", size),
            &encrypted,
            |b, encrypted| {
                let provider = apple_crypto_provider();
                let mut cipher =
                    provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, false);
                b.iter(|| {
                    cipher
                        .decrypt(
                            black_box(&iv),
                            black_box(&[aad.as_slice()]),
                            black_box(encrypted),
                            black_box(&mut output),
                        )
                        .unwrap()
                })
            },
        );

        #[cfg(windows)]
        group.bench_with_input(
            BenchmarkId::new("WinCrypto", size),
            &encrypted,
            |b, encrypted| {
                let provider = wincrypto_provider();
                let mut cipher =
                    provider.srtp_provider.aead_aes_128_gcm().create_cipher(key, false);
                b.iter(|| {
                    cipher
                        .decrypt(
                            black_box(&iv),
                            black_box(&[aad.as_slice()]),
                            black_box(encrypted),
                            black_box(&mut output),
                        )
                        .unwrap()
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// AES-256-GCM (SRTP AEAD) Decrypt Benchmarks
// ============================================================================

fn bench_aes_256_gcm_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("AEAD-AES-256-GCM-Decrypt");

    let key: [u8; 32] = [0x42u8; 32];
    let iv: [u8; 12] = [0x00u8; 12];
    let aad: [u8; 12] = [0x01u8; 12];

    for size in [SMALL_DATA_SIZE, MEDIUM_DATA_SIZE, LARGE_DATA_SIZE] {
        // First encrypt to get valid ciphertext
        let input = get_test_data(size);
        let mut encrypted = vec![0u8; size + 16];

        let provider = openssl_provider();
        let mut cipher = provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, true);
        cipher.encrypt(&iv, &aad, &input, &mut encrypted).unwrap();

        let mut output = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("OpenSSL", size),
            &encrypted,
            |b, encrypted| {
                let provider = openssl_provider();
                let mut cipher =
                    provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, false);
                b.iter(|| {
                    cipher
                        .decrypt(
                            black_box(&iv),
                            black_box(&[aad.as_slice()]),
                            black_box(encrypted),
                            black_box(&mut output),
                        )
                        .unwrap()
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("AWS-LC-RS", size),
            &encrypted,
            |b, encrypted| {
                let provider = aws_lc_rs_provider();
                let mut cipher =
                    provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, false);
                b.iter(|| {
                    cipher
                        .decrypt(
                            black_box(&iv),
                            black_box(&[aad.as_slice()]),
                            black_box(encrypted),
                            black_box(&mut output),
                        )
                        .unwrap()
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("RustCrypto", size),
            &encrypted,
            |b, encrypted| {
                let provider = rust_crypto_provider();
                let mut cipher =
                    provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, false);
                b.iter(|| {
                    cipher
                        .decrypt(
                            black_box(&iv),
                            black_box(&[aad.as_slice()]),
                            black_box(encrypted),
                            black_box(&mut output),
                        )
                        .unwrap()
                })
            },
        );

        #[cfg(target_vendor = "apple")]
        group.bench_with_input(
            BenchmarkId::new("AppleCrypto", size),
            &encrypted,
            |b, encrypted| {
                let provider = apple_crypto_provider();
                let mut cipher =
                    provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, false);
                b.iter(|| {
                    cipher
                        .decrypt(
                            black_box(&iv),
                            black_box(&[aad.as_slice()]),
                            black_box(encrypted),
                            black_box(&mut output),
                        )
                        .unwrap()
                })
            },
        );

        #[cfg(windows)]
        group.bench_with_input(
            BenchmarkId::new("WinCrypto", size),
            &encrypted,
            |b, encrypted| {
                let provider = wincrypto_provider();
                let mut cipher =
                    provider.srtp_provider.aead_aes_256_gcm().create_cipher(key, false);
                b.iter(|| {
                    cipher
                        .decrypt(
                            black_box(&iv),
                            black_box(&[aad.as_slice()]),
                            black_box(encrypted),
                            black_box(&mut output),
                        )
                        .unwrap()
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Cipher Creation Overhead Benchmarks
// ============================================================================

fn bench_cipher_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Cipher-Creation");

    let key_16: [u8; 16] = [0x42u8; 16];
    let key_32: [u8; 32] = [0x42u8; 32];

    // AES-128-CM-SHA1-80 creation
    group.bench_function("OpenSSL/AES-128-CM", |b| {
        let provider = openssl_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aes_128_cm_sha1_80()
                    .create_cipher(key_16, true),
            )
        })
    });

    group.bench_function("AWS-LC-RS/AES-128-CM", |b| {
        let provider = aws_lc_rs_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aes_128_cm_sha1_80()
                    .create_cipher(key_16, true),
            )
        })
    });

    group.bench_function("RustCrypto/AES-128-CM", |b| {
        let provider = rust_crypto_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aes_128_cm_sha1_80()
                    .create_cipher(key_16, true),
            )
        })
    });

    #[cfg(target_vendor = "apple")]
    group.bench_function("AppleCrypto/AES-128-CM", |b| {
        let provider = apple_crypto_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aes_128_cm_sha1_80()
                    .create_cipher(key_16, true),
            )
        })
    });

    #[cfg(windows)]
    group.bench_function("WinCrypto/AES-128-CM", |b| {
        let provider = wincrypto_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aes_128_cm_sha1_80()
                    .create_cipher(key_16, true),
            )
        })
    });

    // AES-128-GCM creation
    group.bench_function("OpenSSL/AES-128-GCM", |b| {
        let provider = openssl_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aead_aes_128_gcm()
                    .create_cipher(key_16, true),
            )
        })
    });

    group.bench_function("AWS-LC-RS/AES-128-GCM", |b| {
        let provider = aws_lc_rs_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aead_aes_128_gcm()
                    .create_cipher(key_16, true),
            )
        })
    });

    group.bench_function("RustCrypto/AES-128-GCM", |b| {
        let provider = rust_crypto_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aead_aes_128_gcm()
                    .create_cipher(key_16, true),
            )
        })
    });

    #[cfg(target_vendor = "apple")]
    group.bench_function("AppleCrypto/AES-128-GCM", |b| {
        let provider = apple_crypto_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aead_aes_128_gcm()
                    .create_cipher(key_16, true),
            )
        })
    });

    #[cfg(windows)]
    group.bench_function("WinCrypto/AES-128-GCM", |b| {
        let provider = wincrypto_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aead_aes_128_gcm()
                    .create_cipher(key_16, true),
            )
        })
    });

    // AES-256-GCM creation
    group.bench_function("OpenSSL/AES-256-GCM", |b| {
        let provider = openssl_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aead_aes_256_gcm()
                    .create_cipher(key_32, true),
            )
        })
    });

    group.bench_function("AWS-LC-RS/AES-256-GCM", |b| {
        let provider = aws_lc_rs_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aead_aes_256_gcm()
                    .create_cipher(key_32, true),
            )
        })
    });

    group.bench_function("RustCrypto/AES-256-GCM", |b| {
        let provider = rust_crypto_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aead_aes_256_gcm()
                    .create_cipher(key_32, true),
            )
        })
    });

    #[cfg(target_vendor = "apple")]
    group.bench_function("AppleCrypto/AES-256-GCM", |b| {
        let provider = apple_crypto_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aead_aes_256_gcm()
                    .create_cipher(key_32, true),
            )
        })
    });

    #[cfg(windows)]
    group.bench_function("WinCrypto/AES-256-GCM", |b| {
        let provider = wincrypto_provider();
        b.iter(|| {
            black_box(
                provider
                    .srtp_provider
                    .aead_aes_256_gcm()
                    .create_cipher(key_32, true),
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sha256,
    bench_sha1_hmac,
    bench_aes_128_ecb_round,
    bench_aes_256_ecb_round,
    bench_aes_128_cm_encrypt,
    bench_aes_128_gcm_encrypt,
    bench_aes_256_gcm_encrypt,
    bench_aes_128_gcm_decrypt,
    bench_aes_256_gcm_decrypt,
    bench_cipher_creation,
);

criterion_main!(benches);
