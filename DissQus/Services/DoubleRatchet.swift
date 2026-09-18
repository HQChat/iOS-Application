//
//  DoubleRatchet.swift
//  DissQus
//
//  KEM double ratchet — the v2 message-key core. Mirrors
//  services/server/lib/double-ratchet.ts byte-for-byte; both sides assert the
//  same services/server/test/helpers/double-ratchet-vectors.json, and both READ
//  that file rather than copying the hex into source (which is what v1 did, so
//  "cross-impl" rested on someone remembering to update two places).
//
//  Replaces RatchetService, which is a symmetric ratchet plus an occasional
//  re-key. Two things were wrong with it, both structural:
//
//    - Every shared secret was a KEM encapsulation to the peer's LONG-TERM
//      pinned key. Decapsulation is deterministic, so one leaked identity secret
//      plus a recorded transcript recomputes every root, chain key and message
//      key that conversation ever used — including epochs whose message keys had
//      been dutifully deleted, because they were recomputable from ciphertexts
//      the network saw.
//    - The root did not chain: deriveEpochRoot(seedA, seedB) ignored the
//      previous root, so "epochs" were independent re-keys, not a ratchet.
//
//  Here the root chains, and every step mixes a secret encapsulated to an
//  EPHEMERAL key that is destroyed after use.
//
//  This file is pure and KEM-free on purpose: it takes shared secrets the caller
//  already holds and returns key material, so it unit-tests without the native
//  HQC library. The HQC calls live in RatchetSession.
//

import Foundation
import CryptoKit

enum DoubleRatchet {

    // MARK: - Operational policy
    //
    // Shared with the TypeScript twin through double-ratchet-vectors.json, which
    // BOTH sides assert. v1 carried these as a prose contract ("MUST stay equal
    // to their Swift twins") that no test checked, so drift was silent.

    /// Cached skipped message keys, across all chains. Bounds memory and the walk.
    static let maxSkipped = 2000

    /// A stepping header costs a public key (7237 B) plus a ciphertext (14421 B)
    /// — ~29 kB base64. Stepping on every direction flip is strongest and what
    /// Signal does, but in a fast exchange that is 29 kB per turn on a phone. So
    /// a flip only steps if the current chain has been used at least once AND
    /// has run long enough or lived long enough.
    ///
    /// COUNT IS THE PRIMARY TRIGGER, time the backstop. It used to be the other
    /// way round, with the interval at 60 s, and that was tuned for a fast
    /// exchange — where it is nearly free. In the pattern messaging actually
    /// has, replies minutes apart, EVERY message crossed the threshold and
    /// carried a full step: a 40-character message that would be a ~300-byte
    /// frame became a ~29 kB one. A hundredfold, on mobile data, in the common
    /// case rather than the edge one.
    ///
    /// At 15 minutes a chain steps on VOLUME during a conversation and on
    /// ELAPSED TIME between them, which is the shape the cost profile wants.
    ///
    /// The cost of waiting is bounded and explicit: a compromise heals within
    /// one step, so these numbers ARE the post-compromise-security window.
    /// Concretely, with the values below: **at most 32 messages, or 15 minutes
    /// of an idle conversation, before a compromise heals.** Widening either
    /// widens that window — a security decision, not only a tuning one.
    ///
    /// Pinned against services/server/test/helpers/double-ratchet-vectors.json,
    /// which both suites assert, so drift fails CI rather than going unnoticed.
    static let ratchetMinStepInterval: TimeInterval = 900
    static let ratchetMaxMessagesPerChain = 32

    private static let salt = Data("salt".utf8)

    private static func hkdf(_ ikm: Data, _ info: String) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: Data(info.utf8),
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }

    struct RootAndChain {
        let root: Data
        let chain: Data
    }

    /// The initial root and the INITIATOR's first sending chain, from the
    /// X3DH-style handshake secrets.
    ///
    /// `ssId` is encapsulated to the peer's pinned identity key and is what
    /// authenticates them — only the real holder can decapsulate it. `ssMt` and
    /// the optional `ssOt` come from published prekeys and are what make the
    /// transcript stop being decryptable once those secrets are gone. Both roles
    /// matter: identity alone has no forward secrecy, prekeys authenticate nobody.
    ///
    /// `ssOt` is absent when the peer's one-time pool was exhausted and the
    /// server served the reusable medium-term key. That is a weaker window, not
    /// a loss of confidentiality, and deliberately not an error.
    static func initRoot(ssId: Data, ssMt: Data, ssOt: Data? = nil) -> RootAndChain {
        var ikm = ssId + ssMt
        if let ssOt { ikm += ssOt }
        return RootAndChain(
            root: hkdf(ikm, "hqchat/v2/init/root"),
            chain: hkdf(ikm, "hqchat/v2/init/chain")
        )
    }

    /// Advance the root by one asymmetric step, yielding the next root and the
    /// chain key for the direction that just stepped.
    ///
    /// This is the line v1 was missing. The new root depends on the OLD root as
    /// well as the fresh secret, so an attacker who learns the state at step n
    /// cannot run it backwards, and one who missed a step cannot rejoin by
    /// capturing later ciphertexts alone.
    static func rootStep(root: Data, ss: Data) -> RootAndChain {
        let ikm = root + ss
        return RootAndChain(
            root: hkdf(ikm, "hqchat/v2/root"),
            chain: hkdf(ikm, "hqchat/v2/chain")
        )
    }

    /// Message key at the current chain position. Delete after use.
    static func messageKey(_ ck: Data) -> Data { hkdf(ck, "hqchat/v2/msg") }

    /// Advance the chain one step. Delete the old ck after use.
    static func chainNext(_ ck: Data) -> Data { hkdf(ck, "hqchat/v2/ck") }

    struct ChainWalk {
        let messageKey: Data
        let ck: Data
        let nextN: Int
        let skipped: [(n: Int, key: Data)]
    }

    /// Walk a receiving chain from `fromN` up to and including `targetN`,
    /// returning the target's message key, the advanced chain, and the keys
    /// skipped on the way (to cache for out-of-order and offline delivery).
    ///
    /// The gap is bounded BEFORE the walk. `n` arrives on a frame header and is
    /// read to CHOOSE the key, so it cannot have been authenticated by the
    /// payload that key opens; each step is an HKDF, and this runs on the
    /// MainActor. Capping only the resulting cache is too late — n = 2^31 would
    /// spend two billion HKDF invocations first. Anything past maxSkipped is
    /// undeliverable regardless, since its keys would be evicted immediately.
    ///
    /// Returns nil rather than throwing where the TS twin throws: the only
    /// caller treats every refusal the same way, and a nil keeps that a normal
    /// outcome instead of an error path the UI might surface.
    static func walkChain(ck: Data, fromN: Int, targetN: Int) -> ChainWalk? {
        guard fromN >= 0, targetN >= fromN else { return nil }
        guard targetN - fromN <= maxSkipped else { return nil }

        var skipped: [(n: Int, key: Data)] = []
        var cur = ck
        var i = fromN
        while i < targetN {
            skipped.append((n: i, key: messageKey(cur)))
            cur = chainNext(cur)
            i += 1
        }
        return ChainWalk(
            messageKey: messageKey(cur),
            ck: chainNext(cur),
            nextN: targetN + 1,
            skipped: skipped
        )
    }

    /// Identifier for a ratchet public key, used to index skipped keys by the
    /// chain they belong to. A skipped key is only meaningful together with the
    /// ratchet key whose chain produced it: `n` repeats on every chain, so
    /// caching by `n` alone would collide across steps and hand back a key from
    /// the wrong chain.
    ///
    /// A digest rather than the key itself because an HQC public key is 7237
    /// bytes and this ends up as a dictionary key in persisted JSON on both sides.
    static func chainId(_ rkPub: Data) -> String {
        let digest = SHA256.hash(data: rkPub)
        return digest.map { String(format: "%02x", $0) }.joined().prefix(32).description
    }
}
