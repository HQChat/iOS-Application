import Foundation
import CryptoKit

// Cross-implementation known-answer vectors for the v2 KEM double ratchet.
//
// This file and services/server/test/double-ratchet.test.ts assert the SAME
// double-ratchet-vectors.json, and both READ it. The v1 Swift test copied the
// hex into its source instead, so "cross-impl" rested on someone remembering to
// update two files — and nothing failed when they did not.
//
// The path arrives as argv[1] from run.sh, so this cannot silently assert a
// stale copy: no file, no test.

print("DoubleRatchet (v2 cross-impl vectors)")

func hexStr(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
func hexData(_ h: String) -> Data {
    var d = Data(); var i = h.startIndex
    while i < h.endIndex {
        let j = h.index(i, offsetBy: 2)
        d.append(UInt8(h[i..<j], radix: 16)!)
        i = j
    }
    return d
}

guard CommandLine.arguments.count > 1 else {
    print("  ✗ no vector path given — run.sh must pass double-ratchet-vectors.json")
    exit(1)
}
let vectorPath = CommandLine.arguments[1]
guard let raw = FileManager.default.contents(atPath: vectorPath),
      let V = try? JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
    print("  ✗ could not read vectors at \(vectorPath)")
    exit(1)
}

func dict(_ o: Any?) -> [String: Any] { (o as? [String: Any]) ?? [:] }
func str(_ o: Any?) -> String { (o as? String) ?? "" }
func int(_ o: Any?) -> Int { (o as? Int) ?? -1 }

let input = dict(V["input"])
let initVec = dict(V["initRoot"])
let stepVec = dict(V["rootStep"])
let chainVec = dict(V["chain"])
let walkVec = dict(V["walkChain"])
let policy = dict(V["policy"])

// The file must be the v2 shape. A v1 file would assert a different protocol
// while looking perfectly healthy.
check(int(V["version"]) == 2, "vector file is version 2")

// Policy constants are part of the contract, not just the KDFs. A smaller cap on
// one side silently drops keys the peer still serves.
check(DoubleRatchet.maxSkipped == int(policy["maxSkipped"]),
      "maxSkipped matches the shared contract")
check(Int(DoubleRatchet.ratchetMinStepInterval * 1000) == int(policy["ratchetMinStepIntervalMs"]),
      "ratchetMinStepInterval matches the shared contract")
check(DoubleRatchet.ratchetMaxMessagesPerChain == int(policy["ratchetMaxMessagesPerChain"]),
      "ratchetMaxMessagesPerChain matches the shared contract")

let ssId = hexData(str(input["ssId"]))
let ssMt = hexData(str(input["ssMt"]))
let ssOt = hexData(str(input["ssOt"]))
let stepSs = hexData(str(input["stepSs"]))
let rkPub = hexData(str(input["rkPub"]))

// KEM shared secrets are 32 bytes since CR-1. The v1 vectors still used 24-byte
// seeds, which no longer represent anything the wire carries.
check(ssId.count == 32 && ssMt.count == 32 && ssOt.count == 32,
      "vector inputs are 32-byte KEM shared secrets")

// --- initRoot -------------------------------------------------------------
let withOt = DoubleRatchet.initRoot(ssId: ssId, ssMt: ssMt, ssOt: ssOt)
let withOtVec = dict(initVec["withOneTime"])
check(hexStr(withOt.root) == str(withOtVec["root"]), "initRoot root matches the vector")
check(hexStr(withOt.chain) == str(withOtVec["chain"]), "initRoot chain matches the vector")

// The exhausted-pool fallback is a DIFFERENT session, not the same one with a
// shorter forward-secrecy window by convention.
let noOt = DoubleRatchet.initRoot(ssId: ssId, ssMt: ssMt)
let noOtVec = dict(initVec["withoutOneTime"])
check(hexStr(noOt.root) == str(noOtVec["root"]), "initRoot without a one-time key matches")
check(hexStr(noOt.chain) == str(noOtVec["chain"]), "…and so does its chain")
check(hexStr(noOt.root) != hexStr(withOt.root), "dropping the one-time secret changes the root")

// --- rootStep -------------------------------------------------------------
let first = DoubleRatchet.rootStep(root: hexData(str(withOtVec["root"])), ss: stepSs)
let firstVec = dict(stepVec["first"])
check(hexStr(first.root) == str(firstVec["root"]), "rootStep root matches the vector")
check(hexStr(first.chain) == str(firstVec["chain"]), "rootStep chain matches the vector")

// The same shared secret against the NEW root gives a different result. This is
// the property v1's deriveEpochRoot lacked — it ignored the previous root, so
// epochs were independent re-keys rather than a ratchet.
let second = DoubleRatchet.rootStep(root: first.root, ss: stepSs)
let secondVec = dict(stepVec["second"])
check(hexStr(second.root) == str(secondVec["root"]), "the second step matches the vector")
check(hexStr(second.chain) == str(secondVec["chain"]), "…and its chain")
check(hexStr(second.root) != hexStr(first.root), "the root chains from the previous root")

// --- messageKey / chainNext ----------------------------------------------
let expectedKeys = (chainVec["messageKeys_0_3"] as? [String]) ?? []
check(expectedKeys.count == 4, "the vector carries four message keys")
var ck = hexData(str(withOtVec["chain"]))
var chainMatches = true
for expected in expectedKeys {
    if hexStr(DoubleRatchet.messageKey(ck)) != expected { chainMatches = false }
    ck = DoubleRatchet.chainNext(ck)
}
check(chainMatches, "message keys 0..3 match the vectors")
check(hexStr(ck) == str(chainVec["afterConsuming_0_3"]), "the chain lands where the vector says")

// --- walkChain ------------------------------------------------------------
guard let walk = DoubleRatchet.walkChain(ck: hexData(str(withOtVec["chain"])), fromN: 0, targetN: 3)
else {
    print("  ✗ walkChain refused a legal gap")
    exit(1)
}
check(hexStr(walk.messageKey) == str(walkVec["messageKey"]), "walkChain target key matches")
check(hexStr(walk.ck) == str(walkVec["ck"]), "walkChain advanced chain matches")
check(walk.nextN == int(walkVec["nextN"]), "walkChain nextN matches")

let expectedSkipped = (walkVec["skipped"] as? [[String: Any]]) ?? []
check(walk.skipped.count == expectedSkipped.count, "walkChain skipped exactly the same positions")
var skippedMatch = walk.skipped.count == expectedSkipped.count
for (i, s) in walk.skipped.enumerated() where i < expectedSkipped.count {
    if s.n != int(expectedSkipped[i]["n"]) || hexStr(s.key) != str(expectedSkipped[i]["key"]) {
        skippedMatch = false
    }
}
check(skippedMatch, "every skipped key matches the vector")

// A skipped key IS the message key of the position walked past — a receiver
// serving one from cache must get exactly what the sender used.
var skippedAreMessageKeys = true
for (i, s) in walk.skipped.enumerated() where i < expectedKeys.count {
    if hexStr(s.key) != expectedKeys[i] { skippedAreMessageKeys = false }
}
check(skippedAreMessageKeys, "skipped keys equal the message keys of those positions")

// --- Bounds ---------------------------------------------------------------
// `n` picks the key, so it is read before the payload can authenticate it.
let hostileStart = Date()
let hostile = DoubleRatchet.walkChain(ck: hexData(str(withOtVec["chain"])),
                                      fromN: 0, targetN: 2_000_000_000)
let hostileElapsed = Date().timeIntervalSince(hostileStart)
check(hostile == nil, "a gap past maxSkipped is refused")
check(hostileElapsed < 0.1, "…in constant time, not by walking it (\(hostileElapsed)s)")

check(DoubleRatchet.walkChain(ck: hexData(str(withOtVec["chain"])),
                              fromN: 0, targetN: DoubleRatchet.maxSkipped) != nil,
      "a gap of exactly maxSkipped is still delivered")
check(DoubleRatchet.walkChain(ck: hexData(str(withOtVec["chain"])),
                              fromN: 0, targetN: DoubleRatchet.maxSkipped + 1) == nil,
      "one past maxSkipped is refused")
check(DoubleRatchet.walkChain(ck: hexData(str(withOtVec["chain"])), fromN: 5, targetN: 4) == nil,
      "a target below the current index is refused")

// --- chainId --------------------------------------------------------------
check(DoubleRatchet.chainId(rkPub) == str(dict(V["chainId"])["ofRkPub"]),
      "chainId matches the vector")

finish()
