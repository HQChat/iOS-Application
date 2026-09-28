import Foundation

// The one ServerConfig symbol MQTTTransport.swift reads, for the slices that
// compile MQTTWireClient without TLSPinning.swift (the wire and codec-edge
// tests, and the mqtt-wire fuzzer). No hqn endpoint: those slices never open a
// real transport.
enum ServerConfig {
    static var hqnEndpoint: HQNEndpoint? { nil }
}
