//
//  IdentityManager.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import Foundation
import Security
import SwiftData
import LocalAuthentication

/// Manages user identity: keypair generation and Keychain storage
/// NOTE: For profile-based identity, use ProfileManager instead
class IdentityManager {
    
    private static let keychainService = "com.dissqus.secretkey"
    private static let publicKeyUserDefaultsKey = "com.dissqus.publickey"

    /// How many prompts this store has raised. Mirrors `ProfileManager`'s
    /// counter, which used to be the only one — so a prompt from HERE was
    /// invisible, and a user reporting "six of them" could be shown a log
    /// containing one.
    private static var promptCount = 0

    /// Check if identity already exists (legacy support).
    ///
    /// Does NOT authenticate. This used to be `getSecretKey() != nil`, i.e. an
    /// existence check that raised a biometric prompt — `kSecUseAuthenticationUI
    /// = Fail` asks the same question without one: the item is there when the
    /// read is refused precisely BECAUSE it needs a user.
    static func hasIdentity() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        let status = BiometricAudit.measure("SecItemCopyMatching",
                                            item: "legacy-identity-key EXISTS?",
                                            expectsPrompt: false) {
            SecItemCopyMatching(query as CFDictionary, nil)
        }
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }
    
    /// Check if profiles exist (new profile-based system)
    static func hasProfiles(modelContext: ModelContext) -> Bool {
        let descriptor = FetchDescriptor<Profile>()
        let profiles = (try? modelContext.fetch(descriptor)) ?? []
        return !profiles.isEmpty
    }
    
    // `generateIdentity`, its private `storeSecretKey`, and `IdentityError` were
    // deleted here.
    //
    // Nothing called them. They were the pre-profiles identity path, left behind
    // when `ProfileManager` took over creation, and what they still held was a
    // SECOND copy of the identity key's access control — the same
    // `.biometryCurrentSet` literal, in a function no build could reach. Two
    // copies of one security decision, one of them unreachable and therefore
    // never corrected, is how the next drift starts.
    //
    // `getSecretKey` below stays: it is live, and reads the legacy
    // single-identity key for accounts created before profiles existed
    // (ChatSession, ConversationRouter).
    
    /// Get the secret key from Keychain (requires biometric authentication)
    /// - Parameter authContext: an already-authenticated `LAContext` to reuse
    ///   (batched Face ID); when nil, a fresh context is created and prompts.
    /// - Returns: Secret key as Data, or nil if not found or authentication failed
    static func getSecretKey(authContext: LAContext? = nil, reason: String = "key read") -> Data? {
        // One line per Keychain read is one line per prompt the user sees — the
        // same contract ProfileManager's counter keeps. Without it this store
        // could prompt and leave no trace at all.
        if authContext == nil {
            promptCount += 1
            print("[IdentityManager] 🔐 legacy-identity prompt #\(promptCount) — \(reason)")
        }
        // Reuse the caller's context if provided, else prompt with a fresh one.
        let context = authContext ?? LAContext()
        context.localizedReason = "Access your private key"

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]
        
        var result: AnyObject?
        let status = BiometricCoordinator.withPrompt {
            BiometricAudit.measure("SecItemCopyMatching",
                                   item: "legacy-identity-key",
                                   expectsPrompt: authContext == nil) {
                SecItemCopyMatching(query as CFDictionary, &result)
            }
        }
        
        guard status == errSecSuccess,
              let data = result as? Data else {
            return nil
        }
        
        return data
    }
    
    /// Get the public key from UserDefaults
    /// - Returns: Public key as hex string, or nil if not found
    static func getPublicKey() -> String? {
        return UserDefaults.standard.string(forKey: publicKeyUserDefaultsKey)
    }
}

// MARK: - Data Extensions

extension Data {
    var hexString: String {
        return map { String(format: "%02x", $0) }.joined()
    }
    
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        
        var i = hexString.startIndex
        for _ in 0..<len {
            let j = hexString.index(i, offsetBy: 2)
            let bytes = hexString[i..<j]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
            i = j
        }
        
        self = data
    }
}

