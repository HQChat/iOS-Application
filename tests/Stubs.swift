// Minimal stand-in so AESService compiles in the test build without linking the
// HQC native library. AESService only reads HQCService.PARAM_K — the 24-byte
// HQC message size — for a seed-length check. The AES/HKDF logic under test is
// the real implementation.
enum HQCService {
    static let PARAM_K = 24

    /// `Friend.ensureMyKEMCiphertext()` reaches for this, so the at-rest slice
    /// needs it to compile. It never runs there: the at-rest tests exercise
    /// sealing and opening message bodies, not key agreement.
    ///
    /// Returning nil rather than fake key material is deliberate — a stub that
    /// produced plausible-looking ciphertext could let a test pass while the real
    /// handshake was broken.
    static func encapsulate(publicKey: Data) throws -> (Data, Data) {
        throw NSError(domain: "HQCServiceStub", code: -1, userInfo: [
            NSLocalizedDescriptionKey: "HQC is not linked into the test binary"
        ])
    }
}

import Foundation

// MARK: - MQTT transport stubs
//
// MQTTWireClient (under test in MQTTWireTests) conforms to MQTTBackend and
// builds a pinned URLSession. The wire CODEC is what the tests exercise, so the
// seam types are stubbed here rather than dragging AuthService/HQC into the test
// build. Keep these in sync with Services/MQTTService.swift + TLSPinning.swift.

enum MQTTEvent {
    case connected
    case disconnected(Error?)
    case message(topic: String, payload: Data)
    case subscribeRefused(topic: String, code: UInt8)
    case publishReplayed(topic: String, attempt: Int)
    case publishAbandoned(topic: String, attempts: Int)
}

protocol MQTTBackend: AnyObject {
    func connect(url: URL, clientID: String, username: String, password: String,
                 willTopic: String, willPayload: Data,
                 onEvent: @escaping (MQTTEvent) -> Void)
    func subscribe(_ topic: String, qos: Int)
    func unsubscribe(_ topic: String)
    func publish(_ topic: String, payload: Data, qos: Int, retained: Bool,
                 onWrite: ((Bool) -> Void)?)
    func disconnect()
}

final class TLSPinningDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    func setOnClose(_ handler: @escaping (Error) -> Void) {}
}
