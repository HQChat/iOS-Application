//
//  KeyVerification.swift
//  DissQus
//
//  Out-of-band key verification (the trust anchor for self-hosting).
//
//  A contact's key arrives from the server, so the server could try to MITM the
//  "E2E" by handing each side its own. Two things stop it, and they answer
//  different questions:
//
//    * the CLIENT ID is a commitment to the key — `id = sha256(hex(pk))` — so a
//      key that does not hash to the id we hold is refused before it is ever
//      pinned. That closes substitution completely, but only relative to the id:
//      it proves "this is the key that id names", not "that id is your friend".
//    * the SAFETY NUMBER, here, answers the second question. It is a
//      deterministic fingerprint of both public keys, compared in person or over
//      another trusted channel (and over a QR for convenience).
//
//  So this screen is what TOFU still rests on, and it is now the only thing that
//  does — everything downstream of "trust the id you were first given" is
//  arithmetic.
//
//  ⚠️ It hashes the raw KEY BYTES, and must keep doing so. Switching it to ids
//  would make it verify a name rather than key material, which is the one job it
//  exists to do.
//

import SwiftUI
import CryptoKit
import CoreImage.CIFilterBuiltins
#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

enum KeyVerification {
    /// A deterministic, symmetric fingerprint of the two public keys (pure logic
    /// lives in KeyFingerprint so it's unit-testable without UI).
    static func safetyNumber(myPublicKey: Data, theirPublicKey: Data) -> String {
        KeyFingerprint.safetyNumber(myPublicKey: myPublicKey, theirPublicKey: theirPublicKey)
    }

    /// A QR image of the safety number's raw digits (for quick visual compare).
    static func qrImage(for safetyNumber: String) -> Image? {
        let payload = safetyNumber.filter(\.isNumber)
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else {
            return nil
        }
        let context = CIContext()
        guard let cg = context.createCGImage(output, from: output.extent) else { return nil }
        #if os(iOS)
        return Image(uiImage: UIImage(cgImage: cg))
        #elseif os(macOS)
        return Image(nsImage: NSImage(cgImage: cg, size: NSSize(width: 240, height: 240)))
        #else
        return nil
        #endif
    }
}

struct KeyVerificationView: View {
    let friend: Friend
    let myPublicKey: Data?
    let onMarkVerified: () -> Void
    let onClearVerification: () -> Void
    var onRotateKeys: () -> Void = {}
    @Environment(\.dismiss) private var dismiss

    private var safety: String? {
        guard let myPublicKey, friend.hasPinnedKey else { return nil }
        return KeyVerification.safetyNumber(myPublicKey: myPublicKey, theirPublicKey: friend.publicKey)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    if friend.isVanished {
                        vanishedNotice
                    }

                    Text("Compare this safety number with **@\(friend.username)** in person or over another trusted channel. If it matches on both devices, your conversation is verified end-to-end.")
                        .font(.callout)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)

                    if let safety {
                        if let qr = KeyVerification.qrImage(for: safety) {
                            qr.resizable().interpolation(.none)
                                .frame(width: 200, height: 200)
                        }
                        Text(safety)
                            .font(.system(.title3, design: .monospaced))
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(Color.gray.opacity(0.12))
                            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                            .padding(.horizontal)
                    } else if !friend.hasPinnedKey {
                        // The directory ships ids; the key is fetched separately
                        // and verified against the id before it is pinned. Until
                        // that lands there is nothing to fingerprint.
                        Text("Waiting for @\(friend.username)'s key. It arrives with the next sync, and is checked against their ID before it's used.")
                            .font(.callout)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                    } else {
                        Text("Safety number unavailable (no active identity).")
                            .foregroundColor(.secondary)
                    }

                    // The ID itself, so the two can be compared as well. It is
                    // a hash of the key rather than a second secret: anyone
                    // holding the key can compute it, which is exactly why it is
                    // safe to show and useless as proof on its own.
                    if !friend.peerID.isEmpty {
                        VStack(spacing: 3) {
                            Text("their ID")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            Text(friend.peerID)
                                .font(.system(.caption, design: .monospaced))
                                .multilineTextAlignment(.center)
                                .textSelection(.enabled)
                        }
                        .padding(.horizontal)
                    }

                    if friend.isKeyVerified {
                        Label("Verified", systemImage: "checkmark.seal.fill")
                            .foregroundColor(.green)
                        Button("Clear verification", role: .destructive) {
                            onClearVerification(); dismiss()
                        }
                    } else {
                        Button {
                            onMarkVerified(); dismiss()
                        } label: {
                            Label("Mark as Verified", systemImage: "checkmark.seal")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .padding(.horizontal)
                        .disabled(!friend.hasPinnedKey || friend.isVanished)
                    }

                    if friend.hasSession, !friend.isVanished {
                        Divider().padding(.horizontal)
                        // "Keys not yet rotated" has no counterpart any more: a
                        // session that exists is a session that ratchets, from
                        // its first message. There is no un-rotated state to
                        // warn about.
                        Text("Forward secrecy active")
                            .font(.footnote)
                            .foregroundColor(.secondary)
                        Button {
                            onRotateKeys(); dismiss()
                        } label: {
                            Label("Rotate keys now", systemImage: "arrow.triangle.2.circlepath")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.large)
                        .padding(.horizontal)
                    }
                }
                .padding(.vertical)
            }
            .navigationTitle("Verify @\(friend.username)")
            .inlineNavTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .sheetSizing()
    }

    /// What used to be a "their key changed — accept it?" prompt.
    ///
    /// There is no accepting to do. A contact's ID is a hash of their key, so a
    /// new key is a new ID is a new contact: the identity this screen belongs to
    /// simply ended. The new one appears in the contact list beside it and has
    /// to be verified on its own — this safety number says nothing about it.
    private var vanishedNotice: some View {
        VStack(spacing: 10) {
            Label("this identity is gone", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundColor(.orange)
            Text("These messages were with an identity that no longer exists. @\(friend.username) now signs in with a different key, which makes them a separate contact — verify that one before writing to it.")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            Text("People re-key by reinstalling, resetting their account, or moving to a new device. If @\(friend.username) did none of those, someone may be using their name.")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(Color.orange.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .padding(.horizontal)
    }
}
