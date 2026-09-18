//
//  FileBus.swift
//  DissQus end-to-end harness
//
//  MQTT, simulated by a directory.
//
//  ── Why a file bus ──────────────────────────────────────────────────────────
//  Everything below the transport in this protocol is deterministic: a frame is
//  bytes, a topic is a string, and delivery is "the other side eventually reads
//  what you wrote". A broker adds ordering, QoS and an ACL — worth testing, and
//  tested by services/server/test/e2e against a real EMQX — but it also needs
//  Docker, a database and two HTTP services, which is precisely why the Swift
//  side has never had an end-to-end test at all.
//
//  So this keeps the part that carries protocol meaning (topics, who may read
//  what, ordering per topic) and drops the part that does not (sockets). What it
//  buys is the first test that runs a WHOLE interaction through the real Swift
//  implementation, from first contact to a verified transcript.
//
//  ── Encoding ────────────────────────────────────────────────────────────────
//  Packets are written as HEX, one line per file, not as raw bytes.
//
//  A frame is binary, and text is the wrong container for binary — a harness
//  that guessed at an encoding would corrupt exactly the thing under test. This
//  mattered more while two formats existed (one binary, one UTF-8 JSON) and the
//  bus had to hold either. Hex has no such failure mode: it survives any editor,
//  any diff, any copy out of a terminal, and a truncated write is visibly
//  truncated rather than subtly wrong. Every packet also carries its SHA-256 in the manifest, and the reader
//  checks it — so a file that changed on disk between write and read is caught
//  here rather than surfacing as a decryption failure three layers up.
//
//  The cost is 2x the bytes on disk. For a test transcript that is nothing, and
//  being able to read the transcript by eye is worth more.
//

import Foundation
import CryptoKit

/// One packet as it sat "on the wire".
struct BusPacket {
    let sequence: Int
    let topic: String
    /// Who published it. The bus knows; a real broker mostly does not, and no
    /// protocol code is allowed to read this — it exists for the transcript.
    let publisher: String
    let payload: Data
    let file: String
}

/// Deterministic randomness, so an injected fault replays exactly.
///
/// splitmix64, the same generator `fuzz/Engine.swift` uses. A fault you cannot
/// reproduce from its seed is an anecdote, not a finding.
struct BusRandom {
    private var state: UInt64
    init(seed: UInt64) { self.state = seed &+ 0x9E3779B97F4A7C15 }
    mutating func next() -> UInt64 {
        state = state &+ 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }
    mutating func int(_ upper: Int) -> Int { upper <= 0 ? 0 : Int(next() % UInt64(upper)) }
    /// True with probability `percent`/100.
    mutating func chance(_ percent: Int) -> Bool { int(100) < percent }
}

/// What the network is allowed to do to a packet on its way across.
///
/// WHY THE HARNESS NEEDS THIS. Without it the bus is a perfect channel: every
/// packet arrives, once, in order, intact. Nothing in the protocol is interesting
/// under those conditions — the ratchet's skipped-key handling, the replay
/// refusal and the out-of-order path are all reachable only when delivery
/// misbehaves, and MQTT at QoS 1 promises *at least* once, not exactly once.
///
/// Every fault is drawn from a seeded generator, so `--faults --seed N` replays
/// byte for byte.
///
/// NOT included: dropping or corrupting a packet the protocol has no way to
/// recover from, which would only prove that a broken channel breaks things. The
/// faults here are the ones a real broker and a real network actually produce.
///
/// NOT APPLIED DURING FIRST CONTACT, and the reason is a limitation worth being
/// explicit about rather than hiding behind a passing test. An `init` travels on
/// the recipient's inbox while messages travel on the conversation topic, so they
/// are different topics and MQTT's per-topic ordering says nothing about which
/// lands first. Reordering across that boundary makes a conversation frame arrive
/// for a session that does not exist yet.
///
/// That is a REAL question — a real client can be handed exactly that — but this
/// harness cannot answer it: `Party` mirrors `ConversationRouter`'s orchestration
/// rather than importing it (`ConversationRouter` is @MainActor over SwiftData),
/// and the mirror has no pending-frame queue. Injecting the fault here would
/// therefore test the harness, not the app. Covering it properly means testing
/// `ConversationRouter` directly, which is Phase 6 work.
///
/// So faults are enabled once the session is up, where duplicates and reorders
/// are ordinary QoS-1 behaviour and the ratchet is the thing under test.
struct BusFaults {
    /// Deliver some packets twice. QoS 1 is at-least-once; a redelivery after a
    /// lost PUBACK is ordinary, and must be refused as a replay rather than
    /// decrypted a second time.
    var duplicatePercent = 0
    /// Hold a packet back and deliver it after the one behind it. The ratchet
    /// caches skipped keys precisely for this.
    var reorderPercent = 0
    /// Drop a packet entirely. The sender does not retransmit here, so this
    /// exercises the receiver's tolerance of a permanent gap.
    var dropPercent = 0

    static let none = BusFaults()

    var enabled: Bool { duplicatePercent > 0 || reorderPercent > 0 || dropPercent > 0 }

    var summary: String {
        enabled
            ? "duplicate \(duplicatePercent)%, reorder \(reorderPercent)%, drop \(dropPercent)%"
            : "none (perfect channel)"
    }
}

/// A file-backed stand-in for the broker.
///
/// Ordering is global and monotonic, which is stronger than MQTT promises across
/// topics and exactly what makes a transcript readable. Per-topic ordering is
/// the property the protocol actually relies on, and it holds.
final class FileBus {

    enum BusError: Error, CustomStringConvertible {
        case corrupt(String)
        case notEntitled(who: String, topic: String)

        var description: String {
            switch self {
            case .corrupt(let f): return "packet file is corrupt or truncated: \(f)"
            case .notEntitled(let who, let topic):
                return "\(who.prefix(8))… has no grant on \(topic)"
            }
        }
    }

    private let root: URL
    private var sequence = 0
    /// Per subscriber, the next index to read on each topic.
    private var cursors: [String: [String: Int]] = [:]
    /// topic → the packets published to it, in order.
    private var log: [String: [BusPacket]] = [:]
    /// The ACL, mirroring `mqtt_acl`: who may touch which topic.
    private var grants: [String: Set<String>] = [:]

    /// What delivery is allowed to do to a packet, and the generator that decides.
    ///
    /// `var`, because a scenario turns faults on PART WAY THROUGH — see the note
    /// on `BusFaults` about first contact.
    var faults: BusFaults
    private var rng: BusRandom
    /// Packets held back by a reorder, per subscriber+topic, to be released on
    /// the NEXT receive. Held rather than dropped: a reorder that never delivers
    /// is a drop, and the two are worth telling apart.
    private var held: [String: [BusPacket]] = [:]
    /// What delivery actually did, for the transcript.
    private(set) var faultLog: [String] = []

    private(set) var manifest: [String] = []

    init(root: URL, faults: BusFaults = .none, seed: UInt64 = 1) throws {
        self.faults = faults
        self.rng = BusRandom(seed: seed)
        self.root = root
        try? FileManager.default.removeItem(at: root)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    // MARK: - The ACL
    //
    // Modelled because it carries protocol meaning: the handshake topic is safe
    // ONLY because a third party has no grant on it, and a harness that let
    // everyone read everything would prove nothing about that.

    func grant(_ who: String, _ topic: String) {
        grants[who, default: []].insert(topic)
    }

    func mayTouch(_ who: String, _ topic: String) -> Bool {
        grants[who]?.contains(topic) ?? false
    }

    // MARK: - Publish / receive

    @discardableResult
    func publish(_ payload: Data, to topic: String, from publisher: String) throws -> BusPacket {
        guard mayTouch(publisher, topic) else {
            throw BusError.notEntitled(who: publisher, topic: topic)
        }
        sequence += 1
        let dir = root.appendingPathComponent(Self.safe(topic), isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let name = String(format: "%04d-%@.hex", sequence, String(publisher.prefix(8)))
        let file = dir.appendingPathComponent(name)
        // Hex, plus a trailing newline so the file is a well-formed text line.
        try (Self.hex(payload) + "\n").write(to: file, atomically: true, encoding: .utf8)

        let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let packet = BusPacket(sequence: sequence, topic: topic, publisher: publisher,
                               payload: payload, file: file.path)
        log[topic, default: []].append(packet)
        manifest.append("\(sequence)\t\(topic)\t\(publisher.prefix(8))\t\(payload.count)B\t\(digest)")
        return packet
    }

    /// Everything published to `topic` that `subscriber` has not yet read.
    ///
    /// Read back FROM THE FILE rather than from memory — the whole point is that
    /// a packet makes a round trip through the filesystem, so an encoding fault
    /// would show up here and not be silently skipped.
    func receive(_ subscriber: String, on topic: String) throws -> [BusPacket] {
        guard mayTouch(subscriber, topic) else {
            throw BusError.notEntitled(who: subscriber, topic: topic)
        }
        let all = log[topic] ?? []
        let from = cursors[subscriber]?[topic] ?? 0

        var out: [BusPacket] = []

        // Anything a previous call held back goes out first — that is what makes
        // a reorder a REORDER and not a drop.
        //
        // BEFORE the "nothing new" check, deliberately. Releasing after it meant
        // a held packet was only ever delivered alongside a later one, so a hold
        // on the LAST packet of a conversation was never released at all and the
        // drain loop spun to its bound. Held packets are the whole point of the
        // reorder fault; they cannot be gated on unrelated traffic arriving.
        let holdKey = "\(subscriber)|\(topic)"
        if let waiting = held[holdKey], !waiting.isEmpty {
            out.append(contentsOf: waiting)
            held[holdKey] = []
        }

        guard from < all.count else { return out }

        for packet in all[from...] {
            // Read back FROM THE FILE. An encoding fault shows up here rather
            // than being silently skipped, and the payload the protocol sees is
            // one that survived a round trip through the filesystem.
            let text = try String(contentsOfFile: packet.file, encoding: .utf8)
            guard let bytes = Self.unhex(text.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                throw BusError.corrupt(packet.file)
            }
            guard bytes == packet.payload else { throw BusError.corrupt(packet.file) }
            let delivered = BusPacket(sequence: packet.sequence, topic: topic,
                                      publisher: packet.publisher, payload: bytes, file: packet.file)

            // MQTT delivers a publisher its own publishes when it subscribes to
            // the topic it published on. Both clients drop those, so the bus
            // hands them over and lets the protocol code do the dropping.
            //
            // FAULTS APPLY ONLY TO OTHER PEOPLE'S PACKETS. Perturbing the echo of
            // your own publish tests the loopback filter, not the protocol.
            guard faults.enabled, packet.publisher != subscriber else {
                out.append(delivered)
                continue
            }

            if rng.chance(faults.dropPercent) {
                note("drop", delivered, to: subscriber)
                continue
            }
            if rng.chance(faults.reorderPercent) {
                held[holdKey, default: []].append(delivered)
                note("hold", delivered, to: subscriber)
                continue
            }
            out.append(delivered)
            if rng.chance(faults.duplicatePercent) {
                out.append(delivered)
                note("duplicate", delivered, to: subscriber)
            }
        }
        cursors[subscriber, default: [:]][topic] = all.count
        return out
    }

    private func note(_ what: String, _ packet: BusPacket, to subscriber: String) {
        faultLog.append("\(what)\tseq \(packet.sequence)\t\(packet.topic)\t→ \(subscriber.prefix(8))…")
    }

    /// Packets a reorder is still holding. A run that ends with anything here has
    /// not actually delivered everything it published, and any count assertion
    /// downstream would be measuring the hold rather than the protocol.
    var heldCount: Int { held.values.reduce(0) { $0 + $1.count } }

    // NOTE: there is deliberately no `flush()`. A held packet is released on the
    // subscriber's NEXT receive, so a scenario drains the channel by polling
    // again — which is what a real client does anyway. A method that claimed to
    // flush but only logged would be worse than not having one.

    /// The transcript, for a human and for the integrity check at the end.
    func writeManifest() throws {
        let header = "seq\ttopic\tfrom\tbytes\tsha256"
        try (([header] + manifest).joined(separator: "\n") + "\n")
            .write(to: root.appendingPathComponent("manifest.tsv"),
                   atomically: true, encoding: .utf8)
    }

    var packetCount: Int { sequence }
    func packets(on topic: String) -> [BusPacket] { log[topic] ?? [] }

    // MARK: - Bytes

    private static func safe(_ topic: String) -> String {
        topic.replacingOccurrences(of: "/", with: "_")
    }

    static func hex(_ d: Data) -> String {
        d.map { String(format: "%02x", $0) }.joined()
    }

    static func unhex(_ s: String) -> Data? {
        guard s.count % 2 == 0 else { return nil }
        var out = Data(capacity: s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            guard let b = UInt8(s[i..<j], radix: 16) else { return nil }
            out.append(b); i = j
        }
        return out
    }
}
