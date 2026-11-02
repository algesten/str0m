import CryptoKit
import Foundation

// Borrowed regions never escape a bridge call. CryptoKit consumes DataProtocol
// regions directly, without an intermediate Data allocation in the bridge.
private struct BorrowedRegions: RandomAccessCollection {
    let pointers: UnsafePointer<UnsafeRawPointer>
    let counts: UnsafePointer<Int>
    let endIndex: Int
    var startIndex: Int { 0 }

    subscript(index: Int) -> UnsafeRawBufferPointer {
        UnsafeRawBufferPointer(start: pointers[index], count: counts[index])
    }
}

private struct BorrowedData: DataProtocol {
    let regions: BorrowedRegions
    let endIndex: Int
    var startIndex: Int { 0 }

    init(_ pointers: UnsafePointer<UnsafeRawPointer>, _ counts: UnsafePointer<Int>, _ count: Int) {
        regions = BorrowedRegions(pointers: pointers, counts: counts, endIndex: count)
        endIndex = regions.reduce(0) { $0 + $1.count }
    }

    subscript(index: Int) -> UInt8 {
        precondition(index >= 0 && index < endIndex)
        var offset = index
        for region in regions {
            if offset < region.count {
                return region[offset]
            }
            offset -= region.count
        }
        preconditionFailure("Invalid borrowed data index")
    }
}

// All pointers are borrowed for the call, except explicitly retained contexts.
@_cdecl("str0m_cryptokit_hash")
public func hash(
    _ size: Int, _ input: UnsafeRawPointer, _ count: Int, _ output: UnsafeMutableRawPointer
) {
    let data = UnsafeRawBufferPointer(start: input, count: count)
    switch size {
    case 20:
        Insecure.SHA1.hash(data: data).withUnsafeBytes { output.copyMemory(from: $0.baseAddress!, byteCount: 20) }
    case 32:
        SHA256.hash(data: data).withUnsafeBytes { output.copyMemory(from: $0.baseAddress!, byteCount: 32) }
    case 48:
        SHA384.hash(data: data).withUnsafeBytes { output.copyMemory(from: $0.baseAddress!, byteCount: 48) }
    default:
        preconditionFailure("Unsupported hash size")
    }
}

@_cdecl("str0m_cryptokit_hmac")
public func hmac(
    _ size: Int, _ key: UnsafeRawPointer, _ keyCount: Int,
    _ inputs: UnsafePointer<UnsafeRawPointer>, _ counts: UnsafePointer<Int>, _ count: Int,
    _ output: UnsafeMutableRawPointer
) {
    let key = SymmetricKey(data: UnsafeRawBufferPointer(start: key, count: keyCount))
    let data = BorrowedData(inputs, counts, count)
    switch size {
    case 20:
        HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key).withUnsafeBytes {
            output.copyMemory(from: $0.baseAddress!, byteCount: 20)
        }
    case 32:
        HMAC<SHA256>.authenticationCode(for: data, using: key).withUnsafeBytes {
            output.copyMemory(from: $0.baseAddress!, byteCount: 32)
        }
    case 48:
        HMAC<SHA384>.authenticationCode(for: data, using: key).withUnsafeBytes {
            output.copyMemory(from: $0.baseAddress!, byteCount: 48)
        }
    default:
        preconditionFailure("Unsupported HMAC size")
    }
}

private protocol HashContext: AnyObject {
    func update(_ data: UnsafeRawBufferPointer)
    func snapshot(_ output: UnsafeMutableRawPointer)
}

private final class HashBox<H: HashFunction>: HashContext {
    private var hash = H()

    func update(_ data: UnsafeRawBufferPointer) {
        hash.update(bufferPointer: data)
    }

    func snapshot(_ output: UnsafeMutableRawPointer) {
        hash.finalize().withUnsafeBytes {
            output.copyMemory(from: $0.baseAddress!, byteCount: $0.count)
        }
    }
}

@_cdecl("str0m_cryptokit_hash_new")
public func hashNew(_ size: Int) -> UnsafeMutableRawPointer {
    let context: any HashContext
    switch size {
    case 32: context = HashBox<SHA256>()
    case 48: context = HashBox<SHA384>()
    default: preconditionFailure("Unsupported hash size")
    }
    return Unmanaged.passRetained(context as AnyObject).toOpaque()
}

private func borrowedHashContext(_ pointer: UnsafeMutableRawPointer) -> any HashContext {
    // Rust only passes live handles returned by hashNew.
    Unmanaged<AnyObject>.fromOpaque(pointer).takeUnretainedValue() as! any HashContext
}

@_cdecl("str0m_cryptokit_hash_update")
public func hashUpdate(_ context: UnsafeMutableRawPointer, _ input: UnsafeRawPointer, _ count: Int) {
    borrowedHashContext(context).update(UnsafeRawBufferPointer(start: input, count: count))
}

@_cdecl("str0m_cryptokit_hash_snapshot")
public func hashSnapshot(_ context: UnsafeMutableRawPointer, _ output: UnsafeMutableRawPointer) {
    borrowedHashContext(context).snapshot(output)
}

@_cdecl("str0m_cryptokit_hash_free")
public func hashFree(_ context: UnsafeMutableRawPointer) {
    Unmanaged<AnyObject>.fromOpaque(context).release()
}

private final class AesGcmKey {
    let key: SymmetricKey

    init(_ bytes: UnsafeRawBufferPointer) {
        key = SymmetricKey(data: bytes)
    }
}

@_cdecl("str0m_cryptokit_aes_gcm_key_new")
public func aesGcmKeyNew(_ key: UnsafeRawPointer, _ count: Int) -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(AesGcmKey(UnsafeRawBufferPointer(start: key, count: count))).toOpaque()
}

@_cdecl("str0m_cryptokit_aes_gcm_key_free")
public func aesGcmKeyFree(_ context: UnsafeMutableRawPointer) {
    Unmanaged<AesGcmKey>.fromOpaque(context).release()
}

// Rust validates nonce sizes, input length and output capacity before calling.
// The wire format is ciphertext || tag; the nonce is passed separately.
// Input and output may alias: all input is consumed before any output is written.
@_cdecl("str0m_cryptokit_aes_gcm")
public func aesGcm(
    _ encrypt: Int32, _ context: UnsafeMutableRawPointer,
    _ nonce: UnsafeRawPointer, _ nonceCount: Int,
    _ input: UnsafeRawPointer, _ count: Int,
    _ aads: UnsafePointer<UnsafeRawPointer>, _ aadCounts: UnsafePointer<Int>, _ aadCount: Int,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        let key = Unmanaged<AesGcmKey>.fromOpaque(context).takeUnretainedValue().key
        let nonce = try AES.GCM.Nonce(data: UnsafeRawBufferPointer(start: nonce, count: nonceCount))
        let data = UnsafeRawBufferPointer(start: input, count: count)
        let aad = BorrowedData(aads, aadCounts, aadCount)
        if encrypt != 0 {
            let sealed = try AES.GCM.seal(data, using: key, nonce: nonce, authenticating: aad)
            // A 12-byte nonce always has a combined representation. Copy just
            // ciphertext || tag, avoiding separate ciphertext/tag Data slices.
            guard let combined = sealed.combined else { return 1 }
            combined.withUnsafeBytes {
                output.update(
                    from: $0.baseAddress!.advanced(by: 12).assumingMemoryBound(to: UInt8.self),
                    count: count + 16
                )
            }
        } else {
            let sealed = try AES.GCM.SealedBox(
                nonce: nonce, ciphertext: data.dropLast(16), tag: data.suffix(16)
            )
            let plaintext = try AES.GCM.open(sealed, using: key, authenticating: aad)
            plaintext.copyBytes(to: output, count: plaintext.count)
        }
        return 0
    } catch CryptoKitError.authenticationFailure {
        return 2
    } catch {
        return 1
    }
}
