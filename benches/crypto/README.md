# Crypto Provider Comparison Benchmarks

Benchmarks comparing cryptographic performance across different crypto backends:
- **OpenSSL** - System OpenSSL library
- **AWS-LC-RS** - AWS's fork of BoringSSL with Rust bindings  
- **RustCrypto** - Pure Rust implementation
- **Apple CommonCrypto** - Apple native crypto framework (macOS only)
- **WinCrypto** - Windows CNG crypto (Windows only)

## Benchmarked Operations

All shared APIs between the crypto providers are benchmarked:

1. **SHA-256** - Hash function
2. **SHA1-HMAC** - STUN message integrity  
3. **AES-128-ECB Round** - Key derivation primitive
4. **AES-256-ECB Round** - Key derivation primitive
5. **AES-128-CM-SHA1-80** - SRTP encryption (CTR mode)
6. **AEAD-AES-128-GCM** - SRTP AEAD encryption/decryption
7. **AEAD-AES-256-GCM** - SRTP AEAD encryption/decryption
8. **Cipher Creation** - Overhead of creating cipher instances

## Running Benchmarks

### Standard Release Build

```bash
cd benches/crypto
cargo bench
```

### With Native CPU Optimizations (Recommended)

For the most realistic performance comparison, enable native CPU optimizations:

```bash
cd benches/crypto
RUSTFLAGS="-C target-cpu=native" cargo bench --release
```

### Run Specific Benchmark

```bash
cargo bench -- SHA256
cargo bench -- "AES-128-GCM"
```

## Output

Results are saved to `target/criterion/` with HTML reports for visualization.

Open `target/criterion/report/index.html` after running benchmarks to see graphical comparisons.

## Notes

- Apple CommonCrypto benchmarks only run on macOS (`target_os = "macos"`)
- WinCrypto benchmarks only run on Windows (`target_os = "windows"`)
- The benchmark uses realistic WebRTC data sizes:
  - 172 bytes (typical RTP packet payload)
  - 1200 bytes (MTU-sized payload)  
  - 8192 bytes (larger bulk payload)
