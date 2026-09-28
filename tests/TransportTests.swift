import Foundation

// Which MQTT transport the app uses, and when (Services/MQTTTransport.swift,
// ServerConfig in TLSPinning.swift). None of this touches a network: the
// failure modes worth pinning are all POLICY — a malformed discovery answer
// that switches transports on, a kill switch that does not switch them off, a
// blocked port that is paid for on every connect instead of once.

print("hqn endpoint parsing")
let x = Data(repeating: 7, count: 32).base64EncodedString()
let q = Data(repeating: 9, count: NoiseHQN.hqcPublicKeyBytes).base64EncodedString()
let good: [String: Any] = ["host": "mqtt.example.org", "port": 443, "keys": [["keyId": 1, "x25519": x, "hqc": q]]]
let ep = HQNEndpoint.parse(good)
check(ep?.host == "mqtt.example.org" && ep?.port == 443 && ep?.keys.count == 1, "a complete answer parses")
check(ep?.url.absoluteString == "hqn://mqtt.example.org:443", "and names itself as an hqn:// URL")
for (label, bad) in [
    ("no host", ["port": 443, "keys": good["keys"]!]),
    ("a host with a path", ["host": "evil/x", "port": 443, "keys": good["keys"]!]),
    ("port 0", ["host": "h", "port": 0, "keys": good["keys"]!]),
    ("no keys", ["host": "h", "port": 443, "keys": [[String: Any]]()]),
    ("a short X25519 key", ["host": "h", "port": 443, "keys": [["keyId": 1, "x25519": "AAAA", "hqc": q]]]),
    ("a short HQC key", ["host": "h", "port": 443, "keys": [["keyId": 1, "x25519": x, "hqc": "AAAA"]]]),
    ("a key id over 255", ["host": "h", "port": 443, "keys": [["keyId": 300, "x25519": x, "hqc": q]]]),
] as [(String, [String: Any])] {
    check(HQNEndpoint.parse(bad) == nil, "refused: \(label)")
}

print("")
print("ServerConfig.hqnEndpoint")
ServerConfig.activeHost = "home.example.org:8443"
check(ServerConfig.hqnEndpoint == nil, "nothing discovered, nothing compiled in: stay on WSS")
check(ServerConfig.hqnDiscoveryIsStale(), "and discovery is due")
ServerConfig.setDiscoveredHQN(ep, enabled: true, for: ServerConfig.host)
check(ServerConfig.hqnEndpoint == ep, "a discovered gateway is used")
check(!ServerConfig.hqnDiscoveryIsStale(), "and the answer is fresh")
check(ServerConfig.hqnDiscoveryIsStale(maxAge: 3600, now: Date().addingTimeInterval(4000)), "…for an hour")
ServerConfig.setDiscoveredHQN(ep, enabled: false, for: ServerConfig.host)
check(ServerConfig.hqnEndpoint == nil, "the server's kill switch turns it off")
ServerConfig.activeHost = "other.example.org"
check(ServerConfig.hqnEndpoint == nil, "one home server's gateway is not another's")
ServerConfig.activeHost = nil

print("")
print("transport selection")
let wss = URL(string: "wss://api.example.org/mqtt")!
let t0 = Date(timeIntervalSince1970: 1_000_000)
do {
    let s = TransportSelector(rememberFor: 3600, minDeadline: 1.5, maxDeadline: 4)
    check(s.plan(hqn: nil, wss: wss, network: "wifi", now: t0).map(\.kind) == [.wss], "no gateway: WSS only")
    let p = s.plan(hqn: ep, wss: wss, network: "wifi", now: t0)
    check(p.map(\.kind) == [.hqn, .wss], "a gateway: hqn first, WSS last — always")
    check(p.first?.deadline == 3 && p.last?.deadline == nil, "hqn gets a deadline; the last resort does not")

    s.record(.hqn, succeeded: false, seconds: nil, network: "wifi", now: t0)
    check(s.plan(hqn: ep, wss: wss, network: "wifi", now: t0.addingTimeInterval(60)).map(\.kind) == [.wss],
          "a network that failed hqn goes straight to WSS")
    check(s.plan(hqn: ep, wss: wss, network: "cellular", now: t0.addingTimeInterval(60)).map(\.kind) == [.hqn, .wss],
          "…that network only")
    check(s.plan(hqn: ep, wss: wss, network: "wifi", now: t0.addingTimeInterval(3601)).map(\.kind) == [.hqn, .wss],
          "…and only until it is time to probe again")

    s.record(.hqn, succeeded: true, seconds: 0.4, network: "wifi", now: t0.addingTimeInterval(3700))
    check(s.plan(hqn: ep, wss: wss, network: "wifi", now: t0.addingTimeInterval(3701)).first?.deadline == 1.5,
          "the deadline tracks a fast network, floored")
    s.record(.hqn, succeeded: true, seconds: 9, network: "wifi", now: t0.addingTimeInterval(3800))
    check(s.plan(hqn: ep, wss: wss, network: "wifi", now: t0.addingTimeInterval(3801)).first?.deadline == 4,
          "…and is capped, so a blackholed port costs a bounded wait")

    s.hqnAllowed = false
    check(s.plan(hqn: ep, wss: wss, network: "wifi", now: t0).map(\.kind) == [.wss], "the local switch turns it off")
}

finish()
