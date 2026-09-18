//
//  DataResetService.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import Foundation
import SwiftData
import Security

/// Service for resetting all app data (useful for development/testing)
@MainActor
class DataResetService {
    
    /// Reset all app data: keychain, UserDefaults, and SwiftData database
    /// - Parameters:
    ///   - modelContext: The SwiftData model context to clear
    ///   - profileManager: Optional ProfileManager to delete profile keychain items
    /// - Returns: True if successful, false otherwise
    static func resetAllData(modelContext: ModelContext, profileManager: ProfileManager? = nil) -> Bool {
        var success = true
        
        // 1. Clear SwiftData database first (so we can get profile IDs for keychain cleanup)
        // But we need to get profile IDs before deleting them
        var profileIds: [String] = []
        if let profileManager = profileManager {
            profileIds = profileManager.profiles.map { $0.id.uuidString }
        } else {
            // Try to fetch profiles directly
            let descriptor = FetchDescriptor<Profile>()
            if let profiles = try? modelContext.fetch(descriptor) {
                profileIds = profiles.map { $0.id.uuidString }
            }
        }
        
        // EVERY step runs, and the result is the AND of all of them.
        //
        // This was `success = success && clearAllKeychainItems(...)` and so on
        // down the list, which reads as "do all three and report whether they all
        // worked" and is not what it does: `&&` SHORT-CIRCUITS, so a false from
        // the keychain step skipped the UserDefaults purge and the database wipe
        // entirely. The user's messages stayed on disk.
        //
        // Not hypothetical, and not only an unsigned-build problem: a keychain
        // item behind `.userPresence` that the user cancels, or any transient
        // OSStatus, produces exactly that false. This function is the App Store
        // account-deletion path, so "the keychain was awkward, so we left the
        // database alone" is the one outcome it must not have.
        //
        // Deleting more than asked is safe here; deleting less is the bug.
        let keychainCleared = clearAllKeychainItems(profileIds: profileIds)
        let defaultsCleared = clearAllUserDefaults()
        let databaseCleared = clearSwiftDataDatabase(modelContext: modelContext)

        success = success && keychainCleared && defaultsCleared && databaseCleared
        return success
    }
    
    /// Delete `com.dissqus.profile.*` items for profiles that are no longer in
    /// the store — the residue of an uninstall, or of an earlier partial reset.
    private static func clearOrphanedProfileItems(knownProfileIds: [String]) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            // Listing attributes does not read the data, so an item behind
            // `.userPresence` is enumerated without raising a prompt.
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess || status == errSecInteractionNotAllowed,
              let items = result as? [[String: Any]] else {
            // Nothing to enumerate is a success; anything else is reported by the
            // targeted deletes around this.
            return true
        }

        var success = true
        let known = Set(knownProfileIds.map { "com.dissqus.profile.\($0)" })
        for item in items {
            guard let service = item[kSecAttrService as String] as? String,
                  service.hasPrefix("com.dissqus.profile."),
                  !known.contains(service) else { continue }
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service
            ]
            let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
            if deleteStatus != errSecSuccess && deleteStatus != errSecItemNotFound {
                print("⚠️ Failed to delete orphaned keychain item \(service): \(deleteStatus)")
                success = false
            } else {
                print("🧹 Removed orphaned keychain items for \(service)")
            }
        }
        return success
    }

    /// Clear all keychain items (legacy and profile-based)
    /// - Parameter profileIds: List of profile IDs to delete keychain items for
    private static func clearAllKeychainItems(profileIds: [String] = []) -> Bool {
        var success = true
        
        // Delete legacy keychain item
        let legacyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.dissqus.secretkey"
        ]
        let legacyStatus = SecItemDelete(legacyQuery as CFDictionary)
        if legacyStatus != errSecSuccess && legacyStatus != errSecItemNotFound {
            print("⚠️ Failed to delete legacy keychain item: \(legacyStatus)")
            success = false
        }
        
        // Delete every per-friend channel key and every at-rest message key.
        // These are keyed by profile/peer rather than by profile service name,
        // so the per-profile loop below would miss them and leave dead key
        // material behind after a "reset all data".
        for service in [AESKeyStore.service, MessageKeyStore.service] {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service
            ]
            let status = SecItemDelete(query as CFDictionary)
            if status != errSecSuccess && status != errSecItemNotFound {
                print("⚠️ Failed to delete keychain items for \(service): \(status)")
                success = false
            }
        }

        // …and the key-protection tier markers. Not key material — they only
        // record which gate each profile's keys were written under — but they
        // are per-profile Keychain items under their own service, so the sweep
        // above and the per-profile loop below both miss them, and "reset all
        // data" would leave behind a list of how many profiles once existed.
        //
        // Its own delete rather than another entry in the loop above: these are
        // written with `kSecUseDataProtectionKeychain`, and on macOS a query
        // without that flag looks in the file-based keychain and finds nothing.
        let markerStatus = SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: KeyProtectionTier.markerService
        ] as CFDictionary)
        if markerStatus != errSecSuccess && markerStatus != errSecItemNotFound {
            print("⚠️ Failed to delete key-protection markers: \(markerStatus)")
            success = false
        }

        // Delete the at-rest key PAIRS. These are `kSecClassKey`, not generic
        // passwords, so every query above misses them — and "Reset All Data"
        // promised "All keys from Keychain" while leaving each profile's
        // `.userPresence` EC private key exactly where it was.
        //
        // No tag filter: Keychain access is app-scoped, these are the only key
        // pairs this app creates, and matching on tags would once again clean up
        // only the profiles still known about.
        //
        // Asked of BOTH keychains, because on macOS there are two and a query
        // reaches exactly one of them. `MessageKeyStore` writes with
        // `kSecUseDataProtectionKeychain` (an Enclave key cannot live anywhere
        // else), while everything older is in the file-based keychain — so a
        // single query would leave half the promise unkept, which is the same
        // shape of gap this block was written to close. On iOS the two forms
        // address the one keychain there is, and the second delete simply finds
        // nothing left.
        for dataProtection in [true, false] {
            let keyPairQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecUseDataProtectionKeychain as String: dataProtection
            ]
            let keyPairStatus = SecItemDelete(keyPairQuery as CFDictionary)
            if keyPairStatus != errSecSuccess && keyPairStatus != errSecItemNotFound {
                print("⚠️ Failed to delete key pairs "
                      + "(\(dataProtection ? "data-protection" : "file") keychain): \(keyPairStatus)")
                success = false
            }
        }

        // The message store's generic-password items — the public half and the
        // scheme marker — live in the data protection keychain alongside the key
        // pair, so they need the same treatment.
        let messageStoreStatus = SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: MessageKeyStore.service
        ] as CFDictionary)
        if messageStoreStatus != errSecSuccess && messageStoreStatus != errSecItemNotFound {
            print("⚠️ Failed to delete message-key store items: \(messageStoreStatus)")
            success = false
        }

        // Profiles this install no longer knows about still own Keychain items:
        // uninstalling on iOS does NOT clear the Keychain, so a reinstall leaves
        // the previous install's identity keys behind and the loop below — which
        // only walks CURRENT profiles — can never reach them. Sweep by service
        // name instead.
        success = success && clearOrphanedProfileItems(knownProfileIds: profileIds)

        // Delete all profile-based keychain items
        for profileId in profileIds {
            let keychainService = "com.dissqus.profile.\(profileId)"
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService
            ]
            let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
            if deleteStatus != errSecSuccess && deleteStatus != errSecItemNotFound {
                print("⚠️ Failed to delete keychain item for profile \(profileId): \(deleteStatus)")
                success = false
            }
        }
        
        return success
    }
    
    /// Clear all UserDefaults keys used by the app
    private static func clearAllUserDefaults() -> Bool {
        // An ALLOWLIST, not `removePersistentDomain(forName:)`. Anything not named
        // here survives a reset, so every omission is a decision.
        //
        // ⚠️ `EulaPrefs.acceptedVersionKey` is deliberately absent. Resetting the
        // app's data destroys identities, contacts and history; it does not
        // un-agree the human sitting in front of it to terms they already read.
        // Re-prompting would be theatre, and Guideline 1.2 asks for agreement,
        // not for a fresh signature per install. It re-prompts by itself when
        // `EulaPrefs.currentVersion` changes, which is the case that should.
        let keys = [
            "com.dissqus.publickey",
            "com.dissqus.seed",
            "com.dissqus.currentUsername",
            // Let the one-shot store migration run again on the fresh store.
            "store.migration.version"
        ]
        
        for key in keys {
            UserDefaults.standard.removeObject(forKey: key)
        }
        
        UserDefaults.standard.synchronize()
        return true
    }
    
    /// Clear all SwiftData entities (profiles, friends, messages)
    private static func clearSwiftDataDatabase(modelContext: ModelContext) -> Bool {
        do {
            // Delete all profiles (cascade will delete friends and messages)
            let profileDescriptor = FetchDescriptor<Profile>()
            let profiles = try modelContext.fetch(profileDescriptor)
            for profile in profiles {
                modelContext.delete(profile)
            }
            
            // Also delete any orphaned friends or messages (shouldn't happen with cascade, but just in case)
            let friendDescriptor = FetchDescriptor<Friend>()
            let friends = try modelContext.fetch(friendDescriptor)
            for friend in friends {
                friend.clearAESKeys() // purge Keychain key material
                modelContext.delete(friend)
            }
            
            let messageDescriptor = FetchDescriptor<Message>()
            let messages = try modelContext.fetch(messageDescriptor)
            for message in messages {
                modelContext.delete(message)
            }
            
            try modelContext.save()
            return true
        } catch {
            print("❌ Failed to clear SwiftData database: \(error)")
            return false
        }
    }
    
    /// Get the path to the SwiftData database file (for manual deletion if needed)
    /// - Returns: The file path, or nil if not found
    static func getDatabasePath() -> String? {
        #if os(macOS)
        let containerPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library")
            .appendingPathComponent("Containers")
            .appendingPathComponent("martin.rougeron.DissQus")
            .appendingPathComponent("Data")
            .appendingPathComponent("Library")
            .appendingPathComponent("Application Support")
            .appendingPathComponent("default.store")
        return containerPath.path
        #else
        // On iOS the SwiftData store lives in the app's own sandbox.
        guard let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return appSupport.appendingPathComponent("default.store").path
        #endif
    }
    
    /// Delete the SwiftData database file directly (use with caution)
    /// - Returns: True if successful, false otherwise
    static func deleteDatabaseFile() -> Bool {
        guard let dbPath = getDatabasePath() else {
            return false
        }
        
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: dbPath) {
            do {
                try fileManager.removeItem(atPath: dbPath)
                print("✅ Deleted database file at: \(dbPath)")
                return true
            } catch {
                print("❌ Failed to delete database file: \(error)")
                return false
            }
        }
        
        return true // File doesn't exist, consider it success
    }
    
    /// Print a summary of all data locations (for debugging)
    static func printDataLocations() {
        print("📁 Data Locations:")
        print("  Keychain:")
        print("    - Legacy: com.dissqus.secretkey")
        print("    - Profiles: com.dissqus.profile.{profileId}")
        print("  UserDefaults:")
        print("    - com.dissqus.publickey")
        print("    - com.dissqus.seed")
        print("    - com.dissqus.currentUsername")
        if let dbPath = getDatabasePath() {
            print("  SwiftData Database:")
            print("    - \(dbPath)")
            let fileManager = FileManager.default
            if fileManager.fileExists(atPath: dbPath) {
                if let attributes = try? fileManager.attributesOfItem(atPath: dbPath),
                   let size = attributes[.size] as? Int64 {
                    print("    - Size: \(ByteCountFormatter.string(fromByteCount: size, countStyle: .file))")
                }
            } else {
                print("    - File does not exist")
            }
        }
    }
}

