//
//  BiometricCoordinator.swift
//  DissQus
//
//  One authentication at a time, app-wide.
//
//  iOS shows one biometric UI. A second request raised while the first is on
//  screen does not queue — the system cancels one of them, and the loser is told
//  "Authentication canceled" even though the user authenticated perfectly well.
//
//  That is not hypothetical: at launch the sign-in read (ProfileManager) and the
//  message-read unlock (MessageKeyStore) were raised within a frame of each
//  other. Sign-in won, the unlock was cancelled, and retries on a fixed 1.5s
//  schedule expired while the user was still looking at the sign-in prompt — so
//  every attempt was cancelled, the rows stayed locked, and nothing asked again.
//
//  There is no way to make the SYNCHRONOUS Keychain reads await anything, so
//  this is not a mutex over both. It is a flag the synchronous side sets around
//  its own prompt, and the asynchronous side waits on before raising one.
//

import Foundation

enum BiometricCoordinator {
    private static let lock = NSLock()
    private static var depth = 0

    /// True while a synchronous, prompting Keychain read is in progress.
    static var isBusy: Bool {
        lock.lock(); defer { lock.unlock() }
        return depth > 0
    }

    /// Bracket a read that may raise a prompt. Reentrant, so nesting is safe.
    static func withPrompt<T>(_ body: () -> T) -> T {
        begin()
        defer { end() }
        return body()
    }

    /// Announce an ASYNCHRONOUS prompt — `LAContext.evaluatePolicy`, which
    /// suspends and so cannot be wrapped in `withPrompt`'s non-escaping closure.
    ///
    /// The flag used to be ONE-WAY: the synchronous side set it, the async side
    /// waited on it. That protects the async side from the sync one and not the
    /// reverse, which is only half the collision this file exists to stop — a
    /// message unlock already on screen did nothing to stop the sign-in read
    /// raising a second prompt beside it, and iOS cancelled one of the two. The
    /// user sees two sheets, answers the first, and is told it was cancelled.
    ///
    /// Callers MUST pair these. `defer { BiometricCoordinator.end() }` on the
    /// line after `begin()`, so a throw cannot leave the app permanently "busy".
    static func begin() {
        lock.lock(); depth += 1; lock.unlock()
    }

    static func end() {
        lock.lock(); depth = max(0, depth - 1); lock.unlock()
    }

    /// Wait for any in-flight prompt to finish, up to `timeout`.
    ///
    /// Returns whether the way is clear. Polled rather than signalled because
    /// the thing being waited on is a synchronous call on another thread that
    /// cannot hand us a continuation.
    static func waitUntilFree(timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while isBusy {
            if Date() >= deadline { return false }
            // `try?` would be wrong here. Task.sleep throws IMMEDIATELY once the
            // task is cancelled, so swallowing it turns this poll into a spin.
            do { try await Task.sleep(nanoseconds: 200_000_000) } catch { return false }
        }
        return true
    }
}
