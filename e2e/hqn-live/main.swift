import Foundation
import CryptoKit

// The real Swift MQTT client over the real network path: MQTTWireClient →
// HQNTransport → hqn/1 (NoiseHQN, real HQC-256) → noise-gw → EMQX, with the
// deployment's authn hook checking a v1 signed CONNECT — and the same client
// over WSS, and a fast failure against a closed port (what the fallback's
// "move on" depends on).
//
// Driven by run.sh, which is driven by services/server/test/e2e/run-local.sh.
// argv[1] is the JSON provision-client.ts printed.

var failures = 0
func check(_ ok: Bool, _ label: String) {
    print(ok ? "  ✓ \(label)" : "  ✗ \(label)")
    if !ok { failures += 1 }
}

guard CommandLine.arguments.count > 1,
      let raw = CommandLine.arguments[1].data(using: .utf8),
      let cfg = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
      let id = cfg["id"] as? String, let keyID = cfg["keyId"] as? String,
      let seedHex = cfg["signingSeedHex"] as? String,
      let serverTime = cfg["serverTime"] as? Double,
      let gw = cfg["gateway"] as? [String: Any], let endpoint = HQNEndpoint.parse(gw),
      let wssText = cfg["wss"] as? String, let wssURL = URL(string: wssText) else {
    print("✗ bad provision JSON"); exit(1)
}

func unhex(_ s: String) -> Data {
    var d = Data(); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); d.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return d
}
let signer = try! Curve25519.Signing.PrivateKey(rawRepresentation: unhex(seedHex))
let clockOffset = serverTime - Date().timeIntervalSince1970
func password() -> String {
    try! MQTTConnectProof.make(clientID: id, keyID: keyID, key: signer,
                               timestamp: Int64((Date().timeIntervalSince1970 + clockOffset).rounded()))
}

/// Connect, subscribe to our own inbox, publish to it, and wait for it to come back.
func roundTrip(_ label: String, url: URL, transport: @escaping (URL) -> ByteTransport) {
    print("")
    print(label)
    let client = MQTTWireClient(makeTransport: transport)
    let connected = DispatchSemaphore(value: 0)
    let received = DispatchSemaphore(value: 0)
    var refusal: String?
    let inbox = "u/\(id)/inbox"
    let started = Date()
    client.connect(url: url, clientID: id, username: id, password: password(),
                   willTopic: "u/\(id)/presence", willPayload: Data(#"{"s":"offline"}"#.utf8)) { e in
        switch e {
        case .connected: connected.signal()
        case .disconnected(let err): refusal = err.map { "\($0)" } ?? "closed"; connected.signal()
        case .message(let topic, let payload):
            if topic == inbox, payload == Data("from swift".utf8) { received.signal() }
        default: break
        }
    }
    let ok = connected.wait(timeout: .now() + 20) == .success && refusal == nil
    check(ok, "CONNACK (\(refusal ?? String(format: "%.0f ms", Date().timeIntervalSince(started) * 1000)))")
    guard ok else { return }
    client.subscribe(inbox, qos: 1)
    Thread.sleep(forTimeInterval: 0.3)
    client.publish(inbox, payload: Data("from swift".utf8), qos: 1, retained: false, onWrite: nil)
    check(received.wait(timeout: .now() + 10) == .success, "a publish to our inbox comes back")
    client.disconnect()
    Thread.sleep(forTimeInterval: 0.3)
}

roundTrip("hqn/1 through noise-gw", url: endpoint.url) { _ in HQNTransport(endpoint: endpoint) }
roundTrip("WSS, the fallback path", url: wssURL) { WSSTransport(url: $0) }

print("")
print("a closed port fails fast")
do {
    let dead = HQNEndpoint(host: "127.0.0.1", port: 1, keys: endpoint.keys)
    let t = HQNTransport(endpoint: dead)
    let done = DispatchSemaphore(value: 0)
    let started = Date()
    t.start(opening: Data([0x10, 0x00]), onReceive: { _ in }, onClose: { _ in done.signal() })
    let fast = done.wait(timeout: .now() + 5) == .success
    check(fast, String(format: "a refused connection is reported in %.0f ms, so the fallback moves on at once",
                       Date().timeIntervalSince(started) * 1000))
}

print("")
if failures > 0 { print("✗ \(failures) live check(s) failed"); exit(1) }
print("✅ Swift client live over hqn/1 and WSS")
