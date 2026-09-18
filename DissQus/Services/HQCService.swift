//
//  HQCService.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import Foundation

/// HQC IND-CCA2 KEM service (SECURITY_AUDIT §KM-1).
///
/// The bare IND-CPA PKE (`encrypt`/`decrypt` with 24-byte chunking) is gone. Key
/// agreement is a KEM encapsulation: `encapsulate(publicKey)` → (ciphertext,
/// sharedSecret); the peer `decapsulate`s the ciphertext with its secret key to
/// recover the same 32-byte shared secret, which callers stretch with HKDF. This
/// mirrors the TypeScript `HqcWrapper` and binds the native wrappers in
/// implement/lib/src/low_wrap.c (hqc_kem_keypair/enc/dec_wrap).
///
/// KM-3 hygiene: the native wrappers write into CALLER-allocated buffers and
/// return an int status (0 = OK), so there is no malloc on the native side and no
/// cross-module `free()` here.
class HQCService {

    // Constants from public_wrapper.h (HQC-256).
    static let SEED_BYTES: Int = 32
    static let PUBLIC_KEY_BYTES: Int = 7237
    static let SECRET_KEY_BYTES: Int = 7333
    static let CIPHERTEXT_BYTES: Int = 14421      // CRYPTO_CIPHERTEXTBYTES (KEM)
    static let SHARED_SECRET_BYTES: Int = 32      // CRYPTO_BYTES

    /// Deterministic KEM keypair from a 32-byte identity seed. The public key is
    /// byte-identical to the pre-KEM build for the same seed (stable identity).
    static func generateKeypair(seed: Data) throws -> (publicKey: Data, secretKey: Data) {
        guard seed.count == SEED_BYTES else { throw HQCError.invalidSeedSize }

        var pk = [UInt8](repeating: 0, count: PUBLIC_KEY_BYTES)
        var sk = [UInt8](repeating: 0, count: SECRET_KEY_BYTES)
        let seedArray = [UInt8](seed)

        let rc = seedArray.withUnsafeBufferPointer { s in
            pk.withUnsafeMutableBufferPointer { pkb in
                sk.withUnsafeMutableBufferPointer { skb in
                    hqc_kem_keypair_wrap(s.baseAddress!, pkb.baseAddress!, skb.baseAddress!)
                }
            }
        }
        guard rc == 0 else { throw HQCError.keygenFailed }
        return (Data(pk), Data(sk))
    }

    /// Encapsulate to a recipient's public key.
    /// - Returns: the KEM `ciphertext` to send, and the 32-byte `sharedSecret` to
    ///   derive keys from. Fresh and unpredictable per call (native draws OS entropy).
    static func encapsulate(publicKey: Data) throws -> (ciphertext: Data, sharedSecret: Data) {
        guard publicKey.count == PUBLIC_KEY_BYTES else { throw HQCError.invalidPublicKeySize }

        var ct = [UInt8](repeating: 0, count: CIPHERTEXT_BYTES)
        var ss = [UInt8](repeating: 0, count: SHARED_SECRET_BYTES)
        let pkArray = [UInt8](publicKey)

        let rc = pkArray.withUnsafeBufferPointer { p in
            ct.withUnsafeMutableBufferPointer { ctb in
                ss.withUnsafeMutableBufferPointer { ssb in
                    hqc_kem_enc_wrap(ctb.baseAddress!, ssb.baseAddress!, p.baseAddress!)
                }
            }
        }
        guard rc == 0 else { throw HQCError.encryptionFailed }
        return (Data(ct), Data(ss))
    }

    /// Decapsulate a KEM ciphertext with our secret key → the 32-byte shared
    /// secret. Constant-time: a malformed/attacker-chosen ciphertext yields a
    /// pseudo-random secret (which won't match the sender's), never an error — so
    /// there is no decryption oracle to probe.
    static func decapsulate(secretKey: Data, ciphertext: Data) throws -> Data {
        guard secretKey.count == SECRET_KEY_BYTES else { throw HQCError.invalidSecretKeySize }
        guard ciphertext.count == CIPHERTEXT_BYTES else { throw HQCError.invalidCiphertextSize }

        var ss = [UInt8](repeating: 0, count: SHARED_SECRET_BYTES)
        let ctArray = [UInt8](ciphertext)
        let skArray = [UInt8](secretKey)

        let rc = ss.withUnsafeMutableBufferPointer { ssb in
            ctArray.withUnsafeBufferPointer { c in
                skArray.withUnsafeBufferPointer { s in
                    hqc_kem_dec_wrap(ssb.baseAddress!, c.baseAddress!, s.baseAddress!)
                }
            }
        }
        guard rc == 0 else { throw HQCError.decryptionFailed }
        return Data(ss)
    }
}

// MARK: - Helper Extensions

extension Data {
    func chunked(into size: Int) -> [Data] {
        var chunks: [Data] = []
        var offset = 0
        
        while offset < count {
            let chunkSize = Swift.min(size, count - offset)
            let chunk = subdata(in: offset..<(offset + chunkSize))
            chunks.append(chunk)
            offset += chunkSize
        }
        
        return chunks
    }
    
    func trimmingTrailingNulls() -> Data {
        var trimmed = self
        while trimmed.last == 0 {
            trimmed.removeLast()
        }
        return trimmed
    }
}

// MARK: - Errors

enum HQCError: LocalizedError {
    case invalidSeedSize
    case invalidPublicKeySize
    case invalidSecretKeySize
    case invalidCiphertextSize
    case keygenFailed
    case encryptionFailed
    case decryptionFailed
    case randomGenerationFailed
    
    var errorDescription: String? {
        switch self {
        case .invalidSeedSize:
            return "Seed must be exactly \(HQCService.SEED_BYTES) bytes"
        case .invalidPublicKeySize:
            return "Public key must be exactly \(HQCService.PUBLIC_KEY_BYTES) bytes"
        case .invalidSecretKeySize:
            return "Secret key must be exactly \(HQCService.SECRET_KEY_BYTES) bytes"
        case .invalidCiphertextSize:
            return "Ciphertext must be exactly \(HQCService.CIPHERTEXT_BYTES) bytes"
        case .keygenFailed:
            return "HQC keypair generation failed"
        case .encryptionFailed:
            return "HQC encryption failed"
        case .decryptionFailed:
            return "HQC decryption failed"
        case .randomGenerationFailed:
            return "Random number generation failed"
        }
    }
}

