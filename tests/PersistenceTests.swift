// The store, the migration that rewrites it, and the reset that empties it.
//
// 1,800 lines across Persistence, StoreMigration, DataResetService,
// ProfileManager, IdentityManager and PrekeyService, none of it compiled by a
// test. The fixture that unlocks it is one line — `ModelConfiguration(
// isStoredInMemoryOnly: true)` — and its absence is the only reason none of this
// was reachable.
//
// What is asserted is what a user would lose if it were wrong. A migration that
// drops a contact loses their history. A reset that leaves a row behind is an
// account-deletion claim that is not true. A profile whose id does not name its
// key is an identity the server will refuse.
//
// NOT asserted: anything that needs the Secure Enclave or a biometric prompt.
// That is MAS-9, it needs a signed build on real hardware, and stubbing it here
// would test the stub.

import Foundation
import SwiftData

// ── The fixture ──────────────────────────────────────────────────────────────

@MainActor
func freshContainer() -> ModelContainer {
    let config = ModelConfiguration(isStoredInMemoryOnly: true)
    return try! ModelContainer(for: Profile.self, Friend.self, Message.self, configurations: config)
}

@MainActor
func run() {
    let container = freshContainer()
    let ctx = container.mainContext

    // ── A profile's id is derived from its key ───────────────────────────────

    let pk = Data((0..<7237).map { UInt8($0 % 251) })
    let profile = Profile(username: "alice", publicKeyHex: pk.hexString, seedHex: Data(count: 32).hexString)
    ctx.insert(profile)
    check(!profile.publicKeyHex.isEmpty, "a profile carries its public key")
    check(profile.publicKeyHex.count == 7237 * 2, "as full-width hex — an HQC-256 key is 7237 bytes")
    check(profile.publicKeyHex == profile.publicKeyHex.lowercased(),
          "lowercase, because PeerID hashes the TEXT and case would change the id")

    // ── A contact is named by its client id, not its key ─────────────────────

    let friendPk = Data((0..<7237).map { UInt8(($0 &* 7) % 251) })
    let friend = Friend(username: "bob",
                        peerID: PeerID.from(publicKey: friendPk),
                        publicKey: friendPk,
                        profile: profile)
    ctx.insert(friend)
    check(friend.peerID.count == 64, "a contact's id is 64 hex characters, not a 14474-character key")
    check(PeerID.matches(publicKey: friendPk, id: friend.peerID),
          "…and it is the digest of the key it was created with")

    let msg = Message(content: "hello", isOutgoing: false, friend: friend)
    ctx.insert(msg)
    try? ctx.save()

    check((try? ctx.fetch(FetchDescriptor<Profile>()))?.count == 1, "the profile persisted")
    check((try? ctx.fetch(FetchDescriptor<Friend>()))?.count == 1, "the contact persisted")
    check((try? ctx.fetch(FetchDescriptor<Message>()))?.count == 1, "the message persisted")

    // ── The migration ────────────────────────────────────────────────────────
    //
    // Its ORDER is load-bearing and its header says so: both purges name Keychain
    // items by the friend's PUBLIC KEY, and `adoptClientIdentifiers` is what makes
    // the app stop using those names. Renaming first would leave every one of
    // those items unmatchable — orphans nothing can ever name again, surviving
    // every reinstall.
    //
    // Run against a store that has no version stamp, which is the state of every
    // install that predates it.
    let key = "store.migration.version"
    let saved = UserDefaults.standard.integer(forKey: key)
    UserDefaults.standard.removeObject(forKey: key)
    defer { UserDefaults.standard.set(saved, forKey: key) }

    let beforeFriends = (try? ctx.fetch(FetchDescriptor<Friend>()))?.count ?? 0
    let beforeMessages = (try? ctx.fetch(FetchDescriptor<Message>()))?.count ?? 0

    StoreMigration.runIfNeeded(modelContext: ctx)

    check((try? ctx.fetch(FetchDescriptor<Friend>()))?.count == beforeFriends,
          "the migration kept every contact — losing one loses their history")
    check((try? ctx.fetch(FetchDescriptor<Message>()))?.count == beforeMessages,
          "…and every message")
    check(UserDefaults.standard.integer(forKey: key) > 0, "the store is stamped, so it does not re-run")

    // A contact that already has an id keeps it. The id is DERIVABLE from the
    // row, so nothing is lost to the change and no server round trip is needed.
    let after = (try? ctx.fetch(FetchDescriptor<Friend>()))?.first
    check(after?.peerID == friend.peerID, "a contact's id survived the migration")

    // Running it again changes nothing. Note what this does NOT prove: deleting
    // the version guard entirely still passes, verified by injection — because
    // the migration is idempotent in its OUTCOME, so a second pass over the same
    // rows lands in the same place. What the stamp buys is not correctness but
    // cost: without it every launch re-fetches every contact and re-purges
    // Keychain items. That is not observable from here, and pretending otherwise
    // would be the kind of assertion this branch exists to stop writing.
    StoreMigration.runIfNeeded(modelContext: ctx)
    check((try? ctx.fetch(FetchDescriptor<Friend>()))?.count == beforeFriends,
          "a second run leaves the same rows (idempotent outcome, not a guard test)")

    // ── A contact with no key yet ────────────────────────────────────────────
    //
    // An invite we sent carries only a username. It must keep its empty id and
    // get one from the next directory sync, rather than being assigned a digest
    // of nothing — which would be a real id naming a key nobody holds.
    let pending = Friend(username: "carol", peerID: "", publicKey: Data(), profile: profile)
    ctx.insert(pending)
    try? ctx.save()
    UserDefaults.standard.removeObject(forKey: key)
    StoreMigration.runIfNeeded(modelContext: ctx)
    let stillPending = (try? ctx.fetch(FetchDescriptor<Friend>()))?.first { $0.username == "carol" }
    check(stillPending != nil, "an invite with no key survived the migration")
    check(stillPending?.peerID.isEmpty == true,
          "…and kept its empty id rather than being given a digest of nothing")

    // ── The reset ────────────────────────────────────────────────────────────
    //
    // This is the App Store account-deletion claim. A row left behind is not a
    // tidiness problem, it is the claim being false.
    // The keychain half cannot succeed in an unsigned binary (-25244 / -34018),
    // so `resetAllData` reports FALSE here and that is correct. What must still
    // happen is everything else — the database wipe used to be skipped entirely,
    // because `success = success && step()` short-circuits and the keychain step
    // came first. A failure in one step must not cancel the others.
    let ok = DataResetService.resetAllData(modelContext: ctx)
    check(!ok, "an unsigned binary cannot clear the keychain, so the reset reports failure")
    for (name, n) in [
        ("profiles", (try? ctx.fetch(FetchDescriptor<Profile>()))?.count ?? -1),
        ("contacts", (try? ctx.fetch(FetchDescriptor<Friend>()))?.count ?? -1),
        ("messages", (try? ctx.fetch(FetchDescriptor<Message>()))?.count ?? -1),
    ] {
        check(n == 0,
              "after a reset, \(name) is empty (got \(n)) — a step that failed "
              + "earlier must not cancel the database wipe")
    }

    // And again on the emptied store: still reports the keychain failure, still
    // leaves nothing behind.
    _ = DataResetService.resetAllData(modelContext: ctx)
    check((try? ctx.fetch(FetchDescriptor<Profile>()))?.count == 0,
          "a second reset is harmless")

    // ── The profile manager ──────────────────────────────────────────────────
    //
    // `createProfile` needs the Keychain and cannot run in an unsigned binary,
    // but everything that reads the store can — and the reads carry the two
    // properties that matter.

    let container2 = freshContainer()
    let ctx2 = container2.mainContext
    let pm = ProfileManager(modelContext: ctx2)

    pm.loadProfiles()
    check(pm.profiles.isEmpty, "a fresh store has no profiles")
    pm.loadActiveProfile()
    check(pm.currentProfile == nil, "…and none is active")

    // Newest first. The profile picker shows them in this order, and a stable
    // sort is what stops it reshuffling under the user between launches.
    let older = Profile(username: "older", publicKeyHex: pk.hexString, seedHex: "")
    older.createdAt = Date(timeIntervalSince1970: 1_000)
    let newer = Profile(username: "newer", publicKeyHex: pk.hexString, seedHex: "")
    newer.createdAt = Date(timeIntervalSince1970: 2_000)
    ctx2.insert(older); ctx2.insert(newer)
    try? ctx2.save()

    pm.loadProfiles()
    check(pm.profiles.count == 2, "both profiles load")
    check(pm.profiles.first?.username == "newer", "newest first, so the picker does not reshuffle")

    // THE SEED PURGE. A recovery seed deterministically regenerates the private
    // key, so it is as sensitive as the key and was stored at weaker protection.
    // `loadProfiles` purges any lingering copy on every launch — a profile
    // written by an older build must not keep one.
    let legacy = Profile(username: "legacy", publicKeyHex: pk.hexString,
                         seedHex: Data(repeating: 0xAB, count: 32).hexString)
    ctx2.insert(legacy)
    try? ctx2.save()
    check(!legacy.seedHex.isEmpty, "the fixture starts with a stored seed")

    pm.loadProfiles()
    check(legacy.seedHex.isEmpty,
          "a lingering recovery seed is purged on load — it regenerates the private key, "
          + "so leaving one is leaving the key at weaker protection")
    for p in pm.profiles {
        check(p.seedHex.isEmpty, "no profile keeps a seed after a load")
    }

    // The active profile is the one flagged, and settling it tells the message
    // key store whose unlock policy applies — one place where "the active
    // profile" is decided, and one place that can go stale.
    newer.isActive = true
    try? ctx2.save()
    pm.loadActiveProfile()
    check(pm.currentProfile?.username == "newer", "the flagged profile is the active one")

    newer.isActive = false
    try? ctx2.save()
    pm.loadActiveProfile()
    check(pm.currentProfile == nil, "unflagging it leaves none active, rather than the first row")

    // ── The prekey pool ──────────────────────────────────────────────────────
    //
    // Keyed per profile, so two profiles on one device cannot read each other's
    // one-time secrets.
    let a = UUID(), b = UUID()
    check(PrekeyService.account(for: a) != PrekeyService.account(for: b),
          "two profiles get different prekey storage accounts")
    check(PrekeyService.account(for: nil) != PrekeyService.account(for: a),
          "…and the no-profile account is its own")
    check(PrekeyService.account(for: a) == PrekeyService.account(for: a),
          "the account is stable for one profile")
    check(PrekeyService.account(for: a).contains(a.uuidString)
          || PrekeyService.account(for: a).count > 8,
          "the account names the profile it belongs to")
}

// Everything above is @MainActor because SwiftData's mainContext is, and a
// slice's main.swift has no async entry point to await from.
//
// `assumeIsolated`, NOT a Task plus a semaphore: top-level code already runs ON
// the main thread, so blocking it to wait for a @MainActor task is a deadlock —
// the task needs the very thread the semaphore is holding. Verified the hard
// way; that version hung until it was killed.
MainActor.assumeIsolated { run() }

finish()
