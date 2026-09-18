//
//  AppError.swift
//  DissQus
//
//  One user-facing error type, so raw transport strings stop reaching the UI.
//

import Foundation

/// A failure worth showing to the user.
///
/// The app used to surface `error.localizedDescription` directly in a system
/// alert titled "Error" — so a dropped socket read as
/// "Not connected to WebSocket server", which is a fact about our own code
/// rather than anything the user can act on. Every presentation path now goes
/// through `userMessage`.
enum AppError: Error, Identifiable, Equatable {
    /// Transport failure. Carries the `URLError.Code` so the message can be
    /// specific without re-parsing localized text.
    case network(URLError.Code)
    /// The server rejected the request. `code` is the server's error code
    /// (e.g. `USERNAME_TAKEN`), `message` its human-readable text.
    case server(code: String?, message: String)
    /// Encryption, key exchange, or secure-channel failure.
    case crypto(String)
    /// Keychain / biometric access failure.
    case keychain(String)
    /// The user's input was rejected before it left the device.
    case validation(String)
    /// Anything not worth its own case.
    case unknown(String)

    var id: String { title + userMessage }

    /// Short headline for the alert.
    var title: String {
        switch self {
        case .network: return "Connection problem"
        case .server: return "Server refused"
        case .crypto: return "Encryption problem"
        case .keychain: return "Key access failed"
        case .validation: return "Check that again"
        case .unknown: return "Something went wrong"
        }
    }

    /// What the user actually reads. Written to say what happened and what,
    /// if anything, they can do about it.
    var userMessage: String {
        switch self {
        case .network(let code):
            switch code {
            case .notConnectedToInternet:
                return "You're offline. Check Wi-Fi or cellular and try again."
            case .networkConnectionLost:
                return "The connection dropped. Reconnecting automatically."
            case .timedOut:
                return "The server took too long to respond."
            case .cannotConnectToHost, .cannotFindHost:
                return "Can't reach the server right now."
            case .secureConnectionFailed, .serverCertificateUntrusted,
                 .serverCertificateHasBadDate, .serverCertificateNotYetValid,
                 .serverCertificateHasUnknownRoot:
                return "The server's certificate was rejected, so the connection was refused."
            default:
                return "The connection failed. Please try again."
            }
        case .server(_, let message):
            return message
        case .crypto(let message):
            return message
        case .keychain(let message):
            return message
        case .validation(let message):
            return message
        case .unknown(let message):
            return message
        }
    }

    /// True when retrying could plausibly succeed — drives whether the alert
    /// offers a "Try again" button.
    var isRetryable: Bool {
        switch self {
        case .network: return true
        case .server, .crypto, .keychain, .validation, .unknown: return false
        }
    }

    /// Wrap an arbitrary `Error`, preserving transport detail where possible.
    static func from(_ error: Error) -> AppError {
        if let appError = error as? AppError { return appError }
        if let urlError = error as? URLError { return .network(urlError.code) }
        return .unknown(error.localizedDescription)
    }
}
