//
//  HQCKem.swift
//  DissQus
//
//  Binds the double ratchet to the real KEM.
//
//  Its own file so RatchetSession.swift depends on nothing but the `RatchetKem`
//  protocol. That is what lets the state machine be compiled and tested against
//  a stub on any machine — the HQC library is a native binary the Swift test
//  runner does not link, and a state machine that could only run where that
//  library exists is one that would go untested.
//

import Foundation

/// The production KEM. A thin adapter so the state machine never imports HQC.
struct HQCKem: RatchetKem {
    func generateKeypair() throws -> (pk: Data, sk: Data) {
        var seed = Data(count: 32)
        _ = seed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let pair = try HQCService.generateKeypair(seed: seed)
        return (pair.publicKey, pair.secretKey)
    }

    func encapsulate(_ pk: Data) throws -> (ct: Data, ss: Data) {
        let r = try HQCService.encapsulate(publicKey: pk)
        return (r.ciphertext, r.sharedSecret)
    }

    func decapsulate(sk: Data, ct: Data) throws -> Data {
        try HQCService.decapsulate(secretKey: sk, ciphertext: ct)
    }
}
