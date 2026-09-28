import Foundation
import CryptoKit

// hqn/1 from the Swift side (Services/NoiseHQN.swift).
//
// The gateway runs the TypeScript implementation (services/server/lib/noise.ts)
// and one byte of disagreement anywhere in the transcript is a handshake that
// fails with "decryption failed" on both ends and nothing else. So the vectors
// are READ from the file the TypeScript suite reads: every random input is
// pinned there, including the KEM's (ciphertext, shared secret), and this side
// must reproduce msg1, read msg2, and land on the same transport keys.

print("hqn/1 handshake")

guard CommandLine.arguments.count > 1 else {
    print("  ✗ no vector path given — run.sh must pass noise-hqn-vectors.json")
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
func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

check((V["protocolName"] as? String) == NoiseHQN.protocolName, "the protocol name matches the gateway's")
check((V["prologueLabel"] as? String) == NoiseHQN.prologueLabel, "the prologue label matches")
check((V["hqnVersion"] as? Int) == Int(NoiseHQN.version), "the version matches")
check(cases.count >= 3, "there are vectors to check")

for c in cases {
    let label = c["label"] as? String ?? "?"
    func field(_ k: String) -> Data { unhex(c[k] as? String ?? "") }
    let keyID = UInt8(c["keyId"] as? Int ?? 0)
    let serverStatic = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: field("serverStaticPrivHex"))
    check(serverStatic.publicKey.rawRepresentation == field("serverStaticPubHex"),
          "\(label): the static key derives the same public key")
    let server = NoiseHQN.ServerKeys(keyID: keyID, x25519: field("serverStaticPubHex"), hqc: field("serverHqcPublicHex"))
    let ct = field("kemCiphertextHex"), ss = field("kemSharedSecretHex")

    do {
        let client = try NoiseHQN.Initiator(
            server: server,
            ephemeral: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: field("clientEphemeralPrivHex")),
            encapsulate: { _ in (ct, ss) })
        let msg1 = try client.writeMessage1(payload: field("payload1Hex"))
        check(msg1.count == (c["msg1Length"] as? Int ?? -1), "\(label): msg1 has the pinned length")
        check(hex(NoiseHQN.hash(msg1)) == (c["msg1Sha256"] as? String ?? ""), "\(label): msg1 matches byte for byte")

        let (payload2, t) = try client.readMessage2(field("msg2Hex"))
        check(payload2 == field("payload2Hex"), "\(label): the gateway's msg2 is read, payload intact")
        check(t.handshakeHash == field("handshakeHashHex"), "\(label): the same handshake hash")

        let plain = field("transportPlainHex")
        check(try t.send.encrypt(ad: Data(), plain) == field("transportUpHex"),
              "\(label): the first upstream frame matches")
        check(try t.receive.decrypt(ad: Data(), field("transportDownHex")) == plain,
              "\(label): the gateway's first downstream frame opens")
    } catch {
        check(false, "\(label): handshake threw \(error)")
    }
}

print("")
print("refusals")
do {
    let c = cases[0]
    func field(_ k: String) -> Data { unhex(c[k] as? String ?? "") }
    let server = NoiseHQN.ServerKeys(keyID: UInt8(c["keyId"] as? Int ?? 0),
                                     x25519: field("serverStaticPubHex"), hqc: field("serverHqcPublicHex"))
    let ct = field("kemCiphertextHex"), ss = field("kemSharedSecretHex")
    func client() throws -> NoiseHQN.Initiator {
        let i = try NoiseHQN.Initiator(
            server: server,
            ephemeral: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: field("clientEphemeralPrivHex")),
            encapsulate: { _ in (ct, ss) })
        _ = try i.writeMessage1(payload: field("payload1Hex"))
        return i
    }

    var tampered = field("msg2Hex")
    tampered[tampered.count - 1] ^= 0x01
    check((try? client().readMessage2(tampered)) == nil, "a bit flip in msg2 is refused")

    var badE = field("msg2Hex")
    badE.replaceSubrange(0..<32, with: Data(count: 32))
    check((try? client().readMessage2(badE)) == nil, "a low-order server ephemeral is refused")

    check((try? client().readMessage2(Data(count: 47))) == nil, "a short msg2 is refused")

    let other = NoiseHQN.ServerKeys(keyID: server.keyID &+ 1, x25519: server.x25519, hqc: server.hqc)
    let wrongKey = try? NoiseHQN.Initiator(
        server: other,
        ephemeral: try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: field("clientEphemeralPrivHex")),
        encapsulate: { _ in (ct, ss) })
    _ = try? wrongKey?.writeMessage1(payload: field("payload1Hex"))
    check((try? wrongKey?.readMessage2(field("msg2Hex"))) == nil,
          "a msg2 made for another key id does not open — the key id is in the prologue")

    let once = try! client()
    check((try? once.writeMessage1(payload: Data())) == nil, "msg1 is written once")
    let fresh = try! NoiseHQN.Initiator(server: server, encapsulate: { _ in (ct, ss) })
    check((try? fresh.readMessage2(field("msg2Hex"))) == nil, "msg2 cannot be read before msg1 is sent")

    check((try? NoiseHQN.Initiator(server: .init(keyID: 1, x25519: Data(count: 31), hqc: server.hqc),
                                   encapsulate: { _ in (ct, ss) })) == nil,
          "a malformed pinned key is refused up front")
    check((try? NoiseHQN.Initiator(server: server, encapsulate: { _ in (Data(count: 5), ss) })
            .writeMessage1(payload: Data())) == nil,
          "a KEM that returns the wrong sizes is refused")
}

print("")
print("transport")
do {
    let key = Data((0..<32).map { UInt8($0) })
    let tx = NoiseHQN.CipherState(key: key), rx = NoiseHQN.CipherState(key: key)
    let f1 = try! tx.encrypt(ad: Data(), Data("1".utf8))
    let f2 = try! tx.encrypt(ad: Data(), Data("2".utf8))
    check((try? rx.decrypt(ad: Data(), f2)) == nil, "a skipped frame is refused")
    check((try? rx.decrypt(ad: Data(), f1)) == Data("1".utf8), "…the right one still opens")
    check((try? rx.decrypt(ad: Data(), f1)) == nil, "a repeated frame is refused")

    let exhausted = NoiseHQN.CipherState(key: key)
    exhausted.__setNonceForTesting(UInt64.max)
    check((try? exhausted.encrypt(ad: Data(), Data())) == nil, "the nonce counter refuses to wrap")

    // Split a stream every which way; the reader must reassemble the same frames.
    let sender = NoiseHQN.CipherState(key: key)
    let wire = try! NoiseHQN.sealFrames(sender, Data("first".utf8)) + NoiseHQN.sealFrames(sender, Data("second".utf8))
    for piece in [1, 2, 3, 7, 1000] {
        var reader = NoiseHQN.FrameReader()
        let receiver = NoiseHQN.CipherState(key: key)
        var out: [String] = []
        var i = wire.startIndex
        while i < wire.endIndex {
            let end = min(i + piece, wire.endIndex)
            reader.push(Data(wire[i..<end]))
            while let f = reader.next() { out.append(String(decoding: try! receiver.decrypt(ad: Data(), f), as: UTF8.self)) }
            i = end
        }
        check(out == ["first", "second"] && reader.pending == 0, "frames reassemble when split every \(piece) bytes")
    }

    let big = Data((0..<(NoiseHQN.maxFramePlaintext * 2 + 99)).map { UInt8(truncatingIfNeeded: $0) })
    let bigWire = try! NoiseHQN.sealFrames(NoiseHQN.CipherState(key: key), big)
    var reader = NoiseHQN.FrameReader()
    reader.push(bigWire)
    let receiver = NoiseHQN.CipherState(key: key)
    var parts = Data(), count = 0
    while let f = reader.next() { parts.append(try! receiver.decrypt(ad: Data(), f)); count += 1 }
    check(count == 3 && parts == big, "a payload over one frame is split into frames that fit a u16")
    check((try? NoiseHQN.frame(Data(count: NoiseHQN.maxFrame + 1))) == nil, "no frame exceeds the u16 length")
    check(try! NoiseHQN.sealFrames(NoiseHQN.CipherState(key: key), Data()).isEmpty, "nothing to send is no frames")
}

print("")
print("primitives")
do {
    // RFC 7748 §6.1.
    let alice = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let bobPub = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    check(hex(try! NoiseHQN.dh(alice, bobPub)) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
          "X25519 matches RFC 7748")
    // The Noise HKDF is RFC 5869 HKDF with the chaining key as salt, empty info.
    let ck = Data(repeating: 7, count: 32), ikm = Data(repeating: 9, count: 32)
    let (a, b) = NoiseHQN.hkdf2(ck, ikm)
    let rfc = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: ck, info: Data(), outputByteCount: 64)
        .withUnsafeBytes { Data($0) }
    check(rfc == a + b, "hkdf2 is the Noise HKDF")
}

print("")
print("published Noise_NK_25519_ChaChaPoly_SHA256 vector (cacophony)")
if CommandLine.arguments.count > 2,
   let nkRaw = FileManager.default.contents(atPath: CommandLine.arguments[2]),
   let nkFile = try? JSONSerialization.jsonObject(with: nkRaw) as? [String: Any],
   let v = nkFile["vector"] as? [String: Any],
   let m = v["messages"] as? [[String: String]] {
    func f(_ k: String) -> Data { unhex(v[k] as? String ?? "") }
    do {
        let initE = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: f("init_ephemeral"))
        let respE = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: f("resp_ephemeral"))
        let respS = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: f("resp_static"))
        check(respS.publicKey.rawRepresentation == f("init_remote_static"), "the responder static matches the pinned one")

        // Initiator: -> e, es
        let i = NoiseHQN.SymmetricState(protocolName: "Noise_NK_25519_ChaChaPoly_SHA256")
        i.mixHash(f("init_prologue")); i.mixHash(f("init_remote_static"))
        let e = initE.publicKey.rawRepresentation
        i.mixHash(e); i.mixKey(try NoiseHQN.dh(initE, f("init_remote_static")))
        let m1 = e + (try i.encryptAndHash(unhex(m[0]["payload"]!)))
        check(m1 == unhex(m[0]["ciphertext"]!), "message 1 matches")

        // Responder: <- e, ee
        let r = NoiseHQN.SymmetricState(protocolName: "Noise_NK_25519_ChaChaPoly_SHA256")
        r.mixHash(f("resp_prologue")); r.mixHash(respS.publicKey.rawRepresentation)
        let re = Data(m1.prefix(32))
        r.mixHash(re); r.mixKey(try NoiseHQN.dh(respS, re))
        check(try r.decryptAndHash(Data(m1.dropFirst(32))) == unhex(m[0]["payload"]!), "message 1 opens")
        let re2 = respE.publicKey.rawRepresentation
        r.mixHash(re2); r.mixKey(try NoiseHQN.dh(respE, re))
        let m2 = re2 + (try r.encryptAndHash(unhex(m[1]["payload"]!)))
        check(m2 == unhex(m[1]["ciphertext"]!), "message 2 matches")

        i.mixHash(re2); i.mixKey(try NoiseHQN.dh(initE, re2))
        check(try i.decryptAndHash(Data(m2.dropFirst(32))) == unhex(m[1]["payload"]!), "message 2 opens")
        check(i.h == f("handshake_hash") && r.h == f("handshake_hash"), "the handshake hash matches")

        let (iSend, iRecv) = i.split()
        let (rRecv, rSend) = r.split()
        var transportOK = true
        for k in 2..<m.count {
            let fromInitiator = k % 2 == 0
            let ct = try (fromInitiator ? iSend : rSend).encrypt(ad: Data(), unhex(m[k]["payload"]!))
            let pt = try (fromInitiator ? rRecv : iRecv).decrypt(ad: Data(), ct)
            if ct != unhex(m[k]["ciphertext"]!) || pt != unhex(m[k]["payload"]!) { transportOK = false }
        }
        check(transportOK, "all \(m.count - 2) transport messages match")
    } catch {
        check(false, "the published NK vector threw \(error)")
    }
} else {
    check(false, "the published NK vector file was given and readable")
}

print("")
print("real HQC-256")
do {
    // The pinned vectors inject the KEM; this runs the real library once, so the
    // injected seam is not the only path ever exercised.
    let kp = try HQCService.generateKeypair(seed: Data((0..<32).map { UInt8($0) }))
    let server = NoiseHQN.ServerKeys(keyID: 1, x25519: Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation,
                                     hqc: kp.publicKey)
    let msg1 = try NoiseHQN.Initiator(server: server, encapsulate: { pk in
        let r = try HQCService.encapsulate(publicKey: pk)
        return (r.0, r.1)
    }).writeMessage1(payload: Data("c".utf8))
    check(msg1.count == 32 + NoiseHQN.hqcCiphertextBytes + 16 + 1 + 16, "msg1 with a real HQC ciphertext has the expected size")
} catch {
    check(false, "real HQC encapsulation threw \(error)")
}

finish()
