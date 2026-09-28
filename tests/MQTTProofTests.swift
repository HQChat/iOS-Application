import Foundation
import CryptoKit

// The v1 MQTT CONNECT proof, from the Swift side (Services/MQTTConnectProof.swift).
//
// The auth hook refuses a CONNECT whose signed bytes differ from its own by one
// byte, and says only "deny" — a client that got the encoding wrong would sit
// in a reconnect loop with nothing in either log about why. So the vectors are
// READ from the file services/server/test/mqtt-proof.test.ts reads.
//
// CryptoKit's Ed25519 signer is randomized, so it cannot reproduce the pinned
// (RFC 8032, deterministic) signatures byte for byte. What it CAN show is the
// part that has to agree: the signed message and the password, exactly; that
// the pinned signatures verify here; and that a signature made here verifies.

print("MQTT connect proof")

guard CommandLine.arguments.count > 1 else {
    print("  ✗ no vector path given — run.sh must pass mqtt-proof-vectors.json")
    exit(1)
}
guard let raw = FileManager.default.contents(atPath: CommandLine.arguments[1]),
      let V = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
      let cases = V["cases"] as? [[String: Any]] else {
    print("  ✗ could not read vectors at \(CommandLine.arguments[1])")
    exit(1)
}

func unhex(_ s: String) -> Data {
    var d = Data(capacity: s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        d.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return d
}

check((V["version"] as? Int) == 1, "vector file is version 1")
check((V["context"] as? String) == MQTTConnectProof.context, "the signing context matches the server's")
check(cases.count >= 3, "there are vectors to check")

for c in cases {
    let label = c["label"] as? String ?? "?"
    guard let clientID = c["clientid"] as? String, let keyID = c["keyId"] as? String,
          let ts = (c["ts"] as? NSNumber)?.int64Value,
          let nonceHex = c["nonceHex"] as? String, let messageHex = c["messageHex"] as? String,
          let sigHex = c["signatureHex"] as? String, let pubHex = c["publicKeyHex"] as? String,
          let seedHex = c["seedHex"] as? String, let expectedField = c["connectField"] as? String else {
        check(false, "\(label): vector is complete")
        continue
    }
    let nonce = unhex(nonceHex)
    let message = MQTTConnectProof.message(clientID: clientID, keyID: keyID, timestamp: ts, nonce: nonce)
    check(message == unhex(messageHex), "\(label): the signed bytes match")

    let signature = unhex(sigHex)
    check(MQTTConnectProof.password(keyID: keyID, timestamp: ts, nonce: nonce, signature: signature) == expectedField,
          "\(label): the password matches")

    // The same seed yields the same public key in both libraries.
    if let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: unhex(seedHex)) {
        check(key.publicKey.rawRepresentation == unhex(pubHex), "\(label): the seed gives the pinned public key")
        check(key.publicKey.isValidSignature(signature, for: message),
              "\(label): the server-made signature verifies here")
        let ours = try! key.signature(for: message)
        check(key.publicKey.isValidSignature(ours, for: message),
              "\(label): a signature made here verifies")
    } else {
        check(false, "\(label): the seed is a valid Ed25519 key")
    }
}

print("")
print("fresh passwords")
let key = Curve25519.Signing.PrivateKey()
let id = String(repeating: "ab", count: 32)
let keyID = String(repeating: "0f", count: 16)
let a = try! MQTTConnectProof.make(clientID: id, keyID: keyID, key: key, timestamp: 1_790_000_000)
let b = try! MQTTConnectProof.make(clientID: id, keyID: keyID, key: key, timestamp: 1_790_000_000)
check(a != b, "two CONNECTs in the same second still carry different nonces")

let parts = a.split(separator: ".").map(String.init)
check(parts.count == 5 && parts[0] == "v1" && parts[1] == keyID && parts[2] == "1790000000",
      "the password has the v1 shape")
check(parts.count == 5 && parts[3].count == 22 && parts[4].count == 86,
      "nonce and signature are unpadded base64url of 16 and 64 bytes")
check(!a.contains("=") && !a.contains("+") && !a.contains("/"),
      "no standard-base64 characters — the server accepts exactly one spelling")

// Round trip: what we produce verifies against the public key we registered.
if parts.count == 5 {
    func b64url(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }
    if let nonce = b64url(parts[3]), let sig = b64url(parts[4]) {
        let msg = MQTTConnectProof.message(clientID: id, keyID: keyID, timestamp: 1_790_000_000, nonce: nonce)
        check(key.publicKey.isValidSignature(sig, for: msg), "our own password verifies under our public key")
        let other = MQTTConnectProof.message(clientID: String(repeating: "cd", count: 32), keyID: keyID,
                                             timestamp: 1_790_000_000, nonce: nonce)
        check(!key.publicKey.isValidSignature(sig, for: other), "…and not for another client id")
    } else {
        check(false, "the password's fields decode")
    }
}

finish()
