// Certificate pinning — MAS-3, and the one check standing between this client
// and anyone holding a certificate a system root will vouch for.
//
// 287 lines, never compiled into a test slice. The part that matters is not the
// policy (three clauses, easy to read) but `spkiSHA256`, which RECONSTRUCTS the
// DER SubjectPublicKeyInfo by prepending a hand-written ASN.1 header to the raw
// key bytes Security returns. There are four headers in that table, written out
// as hex. Nothing checked them.
//
// A wrong header is not a subtle bug: the SHA-256 of a wrong SPKI matches no pin,
// so every connection is refused and the app cannot reach the server at all —
// with "cancelAuthenticationChallenge" as the only evidence, which looks
// identical to an actual attack. The failure is safe and completely opaque.
//
// So this is a DIFFERENTIAL against OpenSSL: real certificates, real keys, and
// the SPKI digest computed independently by `openssl` rather than restated here.
// A fifth key type would be caught by the same mechanism.
//
// Fixtures come from tests/run.sh, which generates them with openssl and passes
// the directory as argv[1] — Swift has no X.509 writer, and a committed
// certificate expires.

import Foundation
import CryptoKit
import Security

let fixtureDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""

/// One generated certificate: its DER, and the SPKI SHA-256 openssl computed.
struct Fixture {
    let name: String
    let der: Data
    let opensslSPKISHA256: String
}

func loadFixtures() -> [Fixture] {
    guard !fixtureDir.isEmpty else { return [] }
    let fm = FileManager.default
    let names = ((try? fm.contentsOfDirectory(atPath: fixtureDir)) ?? [])
        .filter { $0.hasSuffix(".der") }
        .sorted()
    return names.compactMap { file in
        let base = String(file.dropLast(4))
        guard let der = fm.contents(atPath: "\(fixtureDir)/\(file)"),
              let hash = try? String(contentsOfFile: "\(fixtureDir)/\(base).sha256", encoding: .utf8)
        else { return nil }
        return Fixture(name: base, der: der,
                       opensslSPKISHA256: hash.trimmingCharacters(in: .whitespacesAndNewlines))
    }
}

func certificate(_ f: Fixture) -> SecCertificate? {
    SecCertificateCreateWithData(nil, f.der as CFData)
}

let fixtures = loadFixtures()

check(!fixtures.isEmpty, "openssl produced \(fixtures.count) fixtures (tests/run.sh generates them; with none this slice proves nothing)")

// ── The reconstruction, against the real thing ───────────────────────────────

for f in fixtures {
    guard let cert = certificate(f) else {
        check(false, "\(f.name): the DER loads as a certificate")
        continue
    }
    let ours = TLSPinningDelegate.spkiSHA256(for: cert)
    let oursHex = ours.map { $0.map { String(format: "%02x", $0) }.joined() } ?? "nil"
    check(oursHex == f.opensslSPKISHA256,
          "\(f.name): the reconstructed SPKI digest is openssl's (\(oursHex.prefix(16))…)")
}

// ── The header table ─────────────────────────────────────────────────────────

let rsa = kSecAttrKeyTypeRSA as String
let ec = kSecAttrKeyTypeECSECPrimeRandom as String

check(TLSPinningDelegate.asn1Header(keyType: rsa, sizeInBits: 2048) != nil
      && TLSPinningDelegate.asn1Header(keyType: rsa, sizeInBits: 4096) != nil
      && TLSPinningDelegate.asn1Header(keyType: ec, sizeInBits: 256) != nil
      && TLSPinningDelegate.asn1Header(keyType: ec, sizeInBits: 384) != nil, "a header exists for every key type the origin may present")

// Every header is a DER SEQUENCE. Not a strong check on its own — the
// differential above is — but it catches a transposed first byte immediately,
// and it applies to a new entry the moment someone adds one.
for (name, key, bits) in [("rsa2048", rsa, 2048), ("rsa4096", rsa, 4096),
                          ("ec256", ec, 256), ("ec384", ec, 384)] {
    let h = TLSPinningDelegate.asn1Header(keyType: key, sizeInBits: bits)
    check(h?.first == 0x30, "\(name): the header opens with a DER SEQUENCE")
}

// An unknown type returns nil rather than a plausible-looking header: that cert
// simply cannot match a pin, and the others in the chain are still tried. A
// fallback here would hash the wrong bytes and silently never match.
check(TLSPinningDelegate.asn1Header(keyType: rsa, sizeInBits: 1024) == nil
      && TLSPinningDelegate.asn1Header(keyType: rsa, sizeInBits: 3072) == nil
      && TLSPinningDelegate.asn1Header(keyType: ec, sizeInBits: 521) == nil
      && TLSPinningDelegate.asn1Header(keyType: "not-a-key-type", sizeInBits: 256) == nil, "an unsupported key size has no header")

check(TLSPinningDelegate.asn1Header(keyType: rsa, sizeInBits: 2048)
        != TLSPinningDelegate.asn1Header(keyType: ec, sizeInBits: 256), "RSA and EC headers are not interchangeable")

// ── Matching a chain against a pin set ────────────────────────────────────────

if let first = fixtures.first, let cert = certificate(first),
   let spki = TLSPinningDelegate.spkiSHA256(for: cert) {

    var trust: SecTrust?
    SecTrustCreateWithCertificates(cert as CFTypeRef, SecPolicyCreateBasicX509(), &trust)

    if let t = trust {
        check(TLSPinningDelegate.chainMatchesAnyPin(trust: t, pins: [spki]), "a chain whose key is pinned matches")

        // The whole point. An attacker with a certificate a system root vouches
        // for still has to hold a key we pinned.
        check(!TLSPinningDelegate.chainMatchesAnyPin(trust: t, pins: [Data(repeating: 0xAB, count: 32)]), "a chain whose key is NOT pinned does not match")

        // Fail CLOSED: an empty pin set must not be read as "matches anything"
        // here. (The delegate treats no-pins-configured as a separate, earlier
        // branch — this function itself must never say yes to nothing.)
        check(!TLSPinningDelegate.chainMatchesAnyPin(trust: t, pins: []), "an empty pin set matches nothing")

        // One pin out of several is enough — that is what makes a backup pin
        // work, and rotating a certificate without one bricks every install.
        check(TLSPinningDelegate.chainMatchesAnyPin(
                trust: t, pins: [Data(repeating: 0x01, count: 32), spki, Data(repeating: 0x02, count: 32)]), "any pin in the set is enough")

        // A near-miss must not match: a truncated or padded digest is what a
        // sloppy prefix comparison would accept.
        check(!TLSPinningDelegate.chainMatchesAnyPin(trust: t, pins: [spki.prefix(16)]), "a truncated pin does not match")
        var padded = spki; padded.append(0x00)
        check(!TLSPinningDelegate.chainMatchesAnyPin(trust: t, pins: [padded]), "a padded pin does not match")
    } else {
        check(false, "a SecTrust can be built from the fixture")
    }
}

// ── Two different keys never share a pin ──────────────────────────────────────

if fixtures.count >= 2 {
    var digests = Set<String>()
    for f in fixtures {
        guard let c = certificate(f), let d = TLSPinningDelegate.spkiSHA256(for: c) else { continue }
        digests.insert(d.map { String(format: "%02x", $0) }.joined())
    }
    check(digests.count == fixtures.count, "every generated key hashes to a distinct pin" + " — " + "\(digests.count) distinct digests from \(fixtures.count) certificates")
}

// ── Where the client is pointed ───────────────────────────────────────────────

check({
    ServerConfig.activeHost = "example.test"
    return ServerConfig.authBaseURL.scheme == "https"
        && ServerConfig.apiBaseURL.scheme == "https"
        && ServerConfig.claimBaseURL.scheme == "https"
}(), "every base URL is https, or pinning is irrelevant")

check({
    ServerConfig.activeHost = "example.test"
    let s = ServerConfig.mqttURL.scheme ?? ""
    return s == "wss" || s == "mqtts" || s == "https"
}(), "the MQTT URL is TLS (\(ServerConfig.mqttURL.scheme ?? "nil")) — it carries the session token")

check({
    ServerConfig.activeHost = "pinned.example"
    return ServerConfig.authBaseURL.host == "pinned.example"
        && ServerConfig.apiBaseURL.host == "pinned.example"
        && ServerConfig.mqttURL.host == "pinned.example"
}(), "the active host is what every URL names")

finish()
