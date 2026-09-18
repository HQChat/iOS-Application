//
//  PrekeyService.swift
//  DissQus
//
//  Our own published prekeys, and the secrets that open what peers encapsulate
//  to them.
//
//  These are the ephemeral half of the initial key agreement. Without them,
//  every shared secret in a conversation would be encapsulated to the long-term
//  identity key — and since KEM decapsulation is deterministic, one leaked
//  identity secret plus a recorded transcript would recompute every root, chain
//  key and message key that conversation ever used. The prekey secrets are
//  destroyed after use, which is what makes the transcript stop being
//  decryptable.
//
//  Two tiers, matching services/server/services/db/migrations/003_prekeys.sql:
//    - medium-term: one key, rotated periodically, reused until it is. The
//      fallback when a peer's one-time pool is empty — a weaker window, not a
//      loss of confidentiality.
//    - one-time: single use, consumed by the server when a peer claims it.
//
//  Secrets are per PROFILE, not per friend: the same published key answers every
//  peer who claims it.
//

import Foundation

/// The prekey secrets for one profile, JSON-encoded into the Keychain.
struct PrekeyStore: Codable {
    var mediumPk: Data
    var mediumSk: Data
    /// One-time secrets by id. An entry is dropped the moment it is used, which
    /// is what makes "one-time" true on this side as well as the server's.
    var oneTime: [String: PrekeyPair]
    /// Highest id ever minted, so replenishment never reuses one — ids the
    /// server has handed out are gone from `oneTime` but may still be in flight
    /// inside somebody's unsent `init` frame.
    var nextId: Int
    var rotatedAt: Date

    struct PrekeyPair: Codable {
        var pk: Data
        var sk: Data
    }
}

@MainActor
final class PrekeyService {

    /// How many one-time keys to keep published. The server accepts at most this
    /// many per upload (a key is 14474 hex characters and the body cap is
    /// 256 kB), and this is also the pool depth we aim for.
    static let targetPoolSize = 8

    /// Replenish once the published pool drops to here. Not zero: a peer that
    /// claims while we are offline should still find a one-time key rather than
    /// falling back to the medium-term one.
    static let replenishThreshold = 4

    /// How long a medium-term key stays in service. It is reused across every
    /// handshake that misses the one-time pool, so its lifetime IS the
    /// forward-secrecy window for those sessions.
    static let mediumTermLifetime: TimeInterval = 7 * 24 * 60 * 60

    private let api: APIClient
    /// Resolved on each access rather than captured at init: a profile switch
    /// changes which secrets are the right ones, and a captured id would keep
    /// answering handshakes with the previous profile's keys.
    private let profileID: () -> UUID?

    init(api: APIClient, profileID: @escaping () -> UUID?) {
        self.api = api
        self.profileID = profileID
    }

    private var account: String { Self.account(for: profileID()) }

    /// The Keychain account for a profile's prekey secrets, callable without a
    /// live service — profile deletion needs it and has no reason to build one.
    static func account(for profileID: UUID?) -> String {
        "prekeys.\(profileID?.uuidString ?? "noprofile")"
    }

    /// Drop a profile's prekey secrets. Called on profile deletion, where the
    /// secrets would otherwise outlive everything they could ever open.
    static func clear(profileID: UUID?) {
        AESKeyStore.delete(account(for: profileID))
    }

    private var store: PrekeyStore? {
        get {
            guard let data = AESKeyStore.get(account) else { return nil }
            return try? JSONDecoder().decode(PrekeyStore.self, from: data)
        }
        set {
            AESKeyStore.set(newValue.flatMap { try? JSONEncoder().encode($0) }, account: account)
        }
    }

    /// The secrets needed to answer an inbound `init` frame.
    ///
    /// Returns nil when this profile has never published a bundle, which is a
    /// real state on a fresh install: the answer is to publish, not to guess.
    func secrets(identitySk: Data) -> PrekeySecrets? {
        guard let store else { return nil }
        return PrekeySecrets(identitySk: identitySk, mediumSk: store.mediumSk) { [weak self] id in
            self?.store?.oneTime[String(id)]?.sk
        }
    }

    /// Consume a one-time secret after it has been used to open an `init`.
    ///
    /// Separate from `secrets` so the caller only burns the key on a handshake
    /// that actually succeeded — dropping it on a frame that failed to
    /// decapsulate would let a malformed `init` destroy a usable key.
    func consumeOneTime(id: Int) {
        guard var store else { return }
        guard store.oneTime.removeValue(forKey: String(id)) != nil else { return }
        self.store = store
    }

    /// Make sure this profile has a published bundle, minting and uploading one
    /// if it has none or if the medium-term key is due for rotation.
    ///
    /// Safe to call on every login and every directory sync: it does nothing
    /// when the pool is healthy.
    func ensurePublished() async {
        do {
            if store == nil {
                try await mintAndPublish(rotateMedium: true, count: Self.targetPoolSize)
                return
            }
            if let rotatedAt = store?.rotatedAt,
               Date().timeIntervalSince(rotatedAt) > Self.mediumTermLifetime {
                try await mintAndPublish(rotateMedium: true, count: Self.targetPoolSize)
                return
            }
            // Ask the SERVER how many are left, not our own store: ours still
            // holds every secret we minted, including the ones already claimed.
            // The server's count is the one that says whether a new peer would
            // find a one-time key or fall back.
            let count = try await api.prekeyCount()
            ProtocolLog.record(.prekeyPoolChecked(
                remaining: count.remaining,
                willReplenish: count.remaining <= Self.replenishThreshold))
            if count.remaining <= Self.replenishThreshold {
                try await mintAndPublish(rotateMedium: false,
                                         count: Self.targetPoolSize - count.remaining)
            }
        } catch {
            // Not fatal. A missing bundle costs first-contact-while-offline and
            // degrades new sessions to the medium-term key; it does not break an
            // established conversation, and the next sync tries again.
            dlogPrekey("could not publish prekeys: \(error)")
            ProtocolLog.record(.dropped(stage: "prekey-publish", peerID: nil,
                                        reason: "could not publish our bundle"))
        }
    }

    /// Drop every prekey secret for this profile (account deletion, reset).
    func clear() { Self.clear(profileID: profileID()) }

    // MARK: - Private

    private func mintAndPublish(rotateMedium: Bool, count: Int) async throws {
        guard count > 0 || rotateMedium else { return }
        var store = self.store ?? PrekeyStore(
            mediumPk: Data(), mediumSk: Data(), oneTime: [:], nextId: 0, rotatedAt: .distantPast
        )

        if rotateMedium || store.mediumPk.isEmpty {
            let pair = try Self.freshKeypair()
            store.mediumPk = pair.pk
            store.mediumSk = pair.sk
            store.rotatedAt = Date()
            // Overwriting `mediumSk` drops the old secret rather than keeping it
            // "just in case" — keeping it is exactly what would extend the window
            // this rotation exists to close. An `init` still in flight against the
            // old key fails to decapsulate, and the peer re-handshakes.
        }

        var minted: [(id: Int, prekey: String)] = []
        for _ in 0..<max(0, min(count, Self.targetPoolSize)) {
            let pair = try Self.freshKeypair()
            let id = store.nextId
            store.nextId += 1
            store.oneTime[String(id)] = PrekeyStore.PrekeyPair(pk: pair.pk, sk: pair.sk)
            minted.append((id: id, prekey: pair.pk.hexString))
        }

        // Persist BEFORE publishing. If the upload fails we hold secrets nobody
        // can claim, which costs nothing; publishing first and then failing to
        // persist would advertise keys we cannot open — every peer claiming one
        // would send an `init` we must refuse.
        self.store = store
        try await api.publishPrekeys(medium: store.mediumPk.hexString, oneTime: minted)
        ProtocolLog.record(.prekeysPublished(count: minted.count, rotatedMedium: rotateMedium))
    }

    private static func freshKeypair() throws -> (pk: Data, sk: Data) {
        var seed = Data(count: 32)
        _ = seed.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        let pair = try HQCService.generateKeypair(seed: seed)
        return (pair.publicKey, pair.secretKey)
    }
}

/// Debug-only. Compiled out of Release so key material never reaches production
/// logs (security audit M2).
fileprivate func dlogPrekey(_ message: @autoclosure () -> String) {
    #if DEBUG
    print("[PrekeyService] \(message())")
    #endif
}
