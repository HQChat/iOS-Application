//
//  AESService.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import Foundation
import CryptoKit

/// AES-256-GCM Encryption Service
/// Handles fast symmetric encryption for message content
class AESService {
    
    /// Encrypt plaintext using AES-256-GCM
    /// Format: [IV (12 bytes)][Tag (16 bytes)][Ciphertext] encoded as Base64
    /// - Parameters:
    ///   - plaintext: Text to encrypt
    ///   - key: Symmetric key (32 bytes for AES-256)
    ///   - aad: Cleartext to bind but not carry — the frame header, whose fields
    ///     are read to CHOOSE the key and so cannot be authenticated by the
    ///     payload that key opens. Both peers must pass byte-identical bytes or
    ///     the tag check fails. Empty means plain AES-GCM, as before.
    /// - Returns: Base64-encoded encrypted data
    static func encrypt(plaintext: String, key: SymmetricKey, aad: Data = Data()) throws -> String {
        try encryptRaw(plaintext: plaintext, key: key, aad: aad).base64EncodedString()
    }

    /// Seal to RAW bytes: `[IV 12][tag 16][ct]`.
    ///
    /// The raw form is the real one and base64 is a v2 spelling of it — the v3
    /// frame carries the payload as bytes. One implementation, so the length and
    /// tag rules cannot end up applying to one path and not the other.
    static func encryptRaw(plaintext: String, key: SymmetricKey, aad: Data = Data()) throws -> Data {
        guard let plaintextData = plaintext.data(using: .utf8) else {
            throw AESError.invalidPlaintext
        }

        // Generate random IV (12 bytes for GCM)
        let iv = AES.GCM.Nonce()

        // Encrypt
        let sealedBox = try AES.GCM.seal(plaintextData, using: key,
                                         nonce: iv, authenticating: aad)

        // Format: [IV (12 bytes)][Tag (16 bytes)][Ciphertext]
        var result = Data(iv)
        result.append(sealedBox.tag)
        result.append(sealedBox.ciphertext)
        return result
    }
    
    /// Decrypt ciphertext using AES-256-GCM
    /// - Parameters:
    ///   - ciphertext: Base64-encoded encrypted data
    ///   - key: Symmetric key (32 bytes for AES-256)
    ///   - aad: Must be byte-identical to what the sender bound (see `encrypt`).
    /// - Returns: Decrypted plaintext string
    static func decrypt(ciphertext: String, key: SymmetricKey, aad: Data = Data()) throws -> String {
        guard let data = Data(base64Encoded: ciphertext) else {
            throw AESError.invalidCiphertext
        }
        return try decryptRaw(ciphertext: data, key: key, aad: aad)
    }

    /// `decrypt`, from the raw `[IV 12][tag 16][ct]` bytes a v3 frame carries.
    static func decryptRaw(ciphertext data: Data, key: SymmetricKey, aad: Data = Data()) throws -> String {
        guard data.count >= 28 else {  // 12 (IV) + 16 (tag) minimum
            throw AESError.invalidCiphertext
        }
        
        // Extract components
        // Indexed from `startIndex`, not from 0. This used to take a base64
        // string, which always decodes to a Data based at zero; it now also takes
        // a payload sliced straight out of a v3 frame, and `subdata(in: 12..<28)`
        // on a slice reads the wrong bytes — or traps.
        let base = data.startIndex
        let ivData = data[base..<(base + 12)]
        let tagData = Data(data[(base + 12)..<(base + 28)])
        let encryptedData = Data(data[(base + 28)..<data.endIndex])
        
        // Create nonce from IV
        guard let nonce = try? AES.GCM.Nonce(data: ivData) else {
            throw AESError.invalidIV
        }
        
        // Create sealed box
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encryptedData, tag: tagData)
        
        // Decrypt
        let decryptedData = try AES.GCM.open(sealedBox, using: key, authenticating: aad)
        
        guard let plaintext = String(data: decryptedData, encoding: .utf8) else {
            throw AESError.decryptionFailed
        }
        
        return plaintext
    }
    
    /// Derive the shared per-friend AES key from the two KEM shared secrets using
    /// HKDF-SHA256. The secrets are sorted before derivation so both parties derive
    /// the same key regardless of who initiated. Inputs are the 32-byte KEM shared
    /// secrets (§KM-1) — one we contributed (our encapsulation's `ss`) and one we
    /// decapsulated from the peer's ciphertext.
    /// - Returns: Symmetric key for AES-256
    static func deriveSharedKey(seedA: Data, seedB: Data) throws -> SymmetricKey {
        guard !seedA.isEmpty, !seedB.isEmpty else {
            throw AESError.invalidSeedSize
        }

        // Sort byte-by-byte for deterministic, order-independent derivation.
        let sortedSeeds = seedA.lexicographicallyPrecedes(seedB) ? [seedA, seedB] : [seedB, seedA]
        let combined = sortedSeeds[0] + sortedSeeds[1]

        // HKDF-SHA256 with salt and info (matches the TS deriveSharedKey default).
        let salt = "salt".data(using: .utf8)!
        let info = "info".data(using: .utf8)!

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: combined),
            salt: salt,
            info: info,
            outputByteCount: 32  // AES-256 requires 32 bytes
        )
    }

    /// Auth proof from a KEM shared secret (§KM-1/§KM-2). Mirrors the server's
    /// `authProof(ss)` in lib/secure-transport.ts:
    /// HKDF-SHA256(IKM=ss, salt="salt", info="auth", 32). Returned as raw Data to
    /// base64-encode into the AUTH_VERIFY payload; proves we hold the secret key
    /// (only it could decapsulate `ss`) without ever revealing `ss`.
    static func authProof(ss: Data) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ss),
            salt: "salt".data(using: .utf8)!,
            info: "auth".data(using: .utf8)!,
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }

    /// Derive the per-direction client↔server transport keys from the session
    /// seed exchanged via HQC. Must match the server/bot:
    /// HKDF-SHA256(IKM=seed, salt="salt", info="session-c2s"/"session-s2c", 32).
    /// c2s: this client encrypts / server decrypts. s2c: the reverse.
    static func deriveSessionKeys(seed: Data) -> (c2s: SymmetricKey, s2c: SymmetricKey) {
        let salt = "salt".data(using: .utf8)!
        func key(_ dir: String) -> SymmetricKey {
            HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: seed),
                salt: salt,
                info: ("session-" + dir).data(using: .utf8)!,
                outputByteCount: 32
            )
        }
        return (c2s: key("c2s"), s2c: key("s2c"))
    }
}

// MARK: - Errors

enum AESError: LocalizedError {
    case invalidPlaintext
    case invalidCiphertext
    case invalidIV
    case invalidSeedSize
    case encryptionFailed
    case decryptionFailed
    
    var errorDescription: String? {
        switch self {
        case .invalidPlaintext:
            return "Invalid plaintext encoding"
        case .invalidCiphertext:
            return "Invalid ciphertext format"
        case .invalidIV:
            return "Invalid initialization vector"
        case .invalidSeedSize:
            return "Shared secrets must be non-empty"
        case .encryptionFailed:
            return "AES encryption failed"
        case .decryptionFailed:
            return "AES decryption failed"
        }
    }
}


import Security

/// Stores per-friend AES key material in the Keychain instead of the
/// (plaintext) SwiftData store, so the message database never contains the
/// keys needed to decrypt it. Items are device-only and available after first
/// unlock, so background decryption keeps working — but they are not
/// biometric-gated (that would block background message handling).
enum AESKeyStore {
    static let service = "com.dissqus.aeskeys"

    static func get(_ account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        // §4.6 records these as having NO access control, so they must never
        // prompt. Audited so that claim is checked rather than assumed.
        let status = BiometricAudit.measure("SecItemCopyMatching",
                                            item: "per-conversation key (AESKeyStore)",
                                            expectsPrompt: false) {
            SecItemCopyMatching(query as CFDictionary, &result)
        }
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    static func set(_ data: Data?, account: String) {
        delete(account) // idempotent overwrite
        guard let data else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    static func delete(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
