//
//  StoreMigration.swift
//  DissQus
//
//  One-shot data fixes that SwiftData's schema migration can't express, run
//  once per store on launch:
//
//   1. Backfill `Message.profileID` — messages used to be found by the friend's
//      username alone, so two profiles sharing a contact showed one merged
//      conversation.
//   2. Re-home per-friend Keychain key material under the owning profile, since
//      the old peer-only account name let two profiles overwrite each other's
//      shared channel key.
//   3. Seal plaintext message bodies at rest.
//   4. Backfill `Friend.peerID` and purge every Keychain account named after a
//      public key, now that contacts are identified by `sha256(hex(pk))`.
//
//  Each step is idempotent, so a half-finished run (crash, kill) is safe to
//  repeat.
//

import Foundation
import SwiftData

@MainActor
enum StoreMigration {
    /// Bump when a new step is added; a store stamped lower re-runs everything.
    private static let currentVersion = 2
    private static let versionKey = "store.migration.version"

    static func runIfNeeded(modelContext: ModelContext) {
        let done = UserDefaults.standard.integer(forKey: versionKey)
        guard done < currentVersion else { return }

        let profiles = (try? modelContext.fetch(FetchDescriptor<Profile>())) ?? []
        let fallbackProfileID = (profiles.first { $0.isActive } ?? profiles.first)?.id

        // ORDER MATTERS. Both purges name Keychain accounts by the friend's
        // PUBLIC KEY, and `adoptClientIdentifiers` is what makes the app stop
        // using those names. Renaming first would leave every one of those items
        // unmatchable — orphans nothing can ever name again, surviving every
        // reinstall of the data store.
        purgeV1KeyMaterial(modelContext: modelContext)
        let adopted = adoptClientIdentifiers(modelContext: modelContext)
        let sealed = migrateMessages(modelContext: modelContext, fallbackProfileID: fallbackProfileID)

        try? modelContext.save()
        UserDefaults.standard.set(currentVersion, forKey: versionKey)
        print("[StoreMigration] ✅ complete (\(adopted) contacts re-keyed by client id, "
              + "\(sealed) message bodies sealed at rest)")
    }

    /// Give every contact its client id, and drop the session material that was
    /// filed under its public key.
    ///
    /// The id is `sha256(lowercase-hex(publicKey))`, so it is DERIVABLE from what
    /// the row already holds: no contact, no name and no message history is lost
    /// to the change, and no server round trip is needed to recover them. A row
    /// with no real key yet (an invite we sent, which carries only a username)
    /// keeps its empty id and gets one from the next directory sync.
    ///
    /// The ratchet session does NOT survive, and cannot: the identifier change is
    /// a wire break — `sender` is a different value, the conversation topic is a
    /// different string — so both ends re-handshake regardless. Deleting it here
    /// is what stops it becoming an orphaned Keychain item under a name the app
    /// no longer generates.
    @discardableResult
    private static func adoptClientIdentifiers(modelContext: ModelContext) -> Int {
        guard let friends = try? modelContext.fetch(FetchDescriptor<Friend>()) else { return 0 }

        var adopted = 0
        for friend in friends {
            let pkHex = friend.publicKeyHex
            guard friend.publicKey.count == HQCPublicKeySize else { continue }

            // The v2 session, under the OLD (public-key-named) accounts. Both
            // shapes, since a store old enough may carry the profile-less one.
            if let profileID = friend.profile?.id {
                AESKeyStore.delete(Friend.legacyKeyedAESAccount(
                    profileID: profileID, peerPublicKeyHex: pkHex, suffix: "ratchet"))
            }
            AESKeyStore.delete(Friend.legacyKeyedAESAccount(
                profileID: nil, peerPublicKeyHex: pkHex, suffix: "ratchet"))
            AESKeyStore.delete(Friend.legacyAESAccount(peerPublicKeyHex: pkHex, suffix: "ratchet"))

            let id = PeerID.from(publicKeyHex: pkHex)
            if friend.peerID != id {
                friend.peerID = id
                adopted += 1
            }
        }
        return adopted
    }

    /// Purge v1 channel key material.
    ///
    /// This used to MOVE `aes.<peerPk>.<suffix>` to the profile-scoped account.
    /// There is nothing left worth moving: every one of those accounts holds v1
    /// material — a static channel key, its two seeds, the stored KEM ciphertext,
    /// or an epoch ratchet state — and none of it can open a v2 frame. Carrying
    /// it forward would only leave old message keys sitting in the Keychain.
    ///
    /// Both shapes go: the pre-profile accounts AND the profile-scoped v1 ones.
    /// A friend whose material is deleted simply re-handshakes, which costs one
    /// prekey and no user-visible step.
    ///
    /// Named by the friend's PUBLIC KEY, because that is what these accounts were
    /// filed under. It must therefore run BEFORE `adoptClientIdentifiers`, which
    /// is where the app stops using that name — see `runIfNeeded`.
    private static func purgeV1KeyMaterial(modelContext: ModelContext) {
        guard let friends = try? modelContext.fetch(FetchDescriptor<Friend>()) else { return }

        // The v1 suffix set, spelled out here rather than read from
        // `Friend.aesSuffixes` — that list is now the v2 one ("ratchet"), and
        // pointing this at it would both miss the four dead accounts and delete
        // the live session.
        let v1Suffixes = ["myseed", "myct", "peerseed", "shared"]

        for friend in friends {
            for suffix in v1Suffixes {
                AESKeyStore.delete(
                    Friend.legacyAESAccount(peerPublicKeyHex: friend.publicKeyHex, suffix: suffix))
                if let profileID = friend.profile?.id {
                    AESKeyStore.delete(Friend.legacyKeyedAESAccount(profileID: profileID,
                                                                    peerPublicKeyHex: friend.publicKeyHex,
                                                                    suffix: suffix))
                }
            }
            // A v1 epoch ratchet state lived under the same "ratchet" suffix the
            // v2 session uses. Reading it used to be the purge — the accessor
            // rejects and deletes on a version mismatch — but the accessor names
            // the account by CLIENT ID now, so it can no longer see the old item
            // at all. `adoptClientIdentifiers` deletes it by its real name.
        }
    }

    /// Stamp every message with its owning profile, then seal any plaintext body.
    /// Order matters: sealing keys off `profileID`.
    @discardableResult
    private static func migrateMessages(modelContext: ModelContext, fallbackProfileID: UUID?) -> Int {
        guard let messages = try? modelContext.fetch(FetchDescriptor<Message>()) else { return 0 }

        var sealed = 0
        for message in messages {
            if message.profileID == nil {
                // System messages carry no friend; they belong to whoever was
                // signed in, which is the best guess available after the fact.
                message.profileID = message.friend?.profile?.id ?? fallbackProfileID
            }
            if message.needsAtRestEncryption {
                message.sealAtRest()
                if !message.needsAtRestEncryption { sealed += 1 }
            }
        }

        return sealed
    }
}
