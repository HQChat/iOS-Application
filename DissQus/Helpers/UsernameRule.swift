//
//  UsernameRule.swift
//  DissQus
//
//  One place for what a username may contain — mirroring the server's rule in
//  `services/db/api.ts` (`setUsername`).
//
//  The client used to accept anything non-empty and let the server reject it,
//  which meant a bad handle only surfaced after a round-trip — and, worse, that
//  the app itself was happy to put arbitrary text into a field other clients
//  render and address by. Validating here keeps the two ends honest and makes
//  the failure immediate and explainable.
//

import Foundation

enum UsernameRule {
    /// Same bounds the server enforces.
    static let minLength = 3
    static let maxLength = 32

    /// Handles the server refuses to hand out (see `usernamesBlacklist`). Kept
    /// in sync deliberately: the point is that the app never *offers* a name it
    /// knows will be rejected.
    static let reserved: Set<String> = [
        "admin", "administrator", "root", "system", "support", "help", "contact",
        "info", "security", "test", "tester", "bot", "moderator", "mod",
        "staff", "team", "owner", "founder",
        "helper", "dissqus"
    ]

    /// Human-readable rule, for field hints.
    static let hint = "3–32 characters · letters, numbers and _ only"

    /// The canonical form we send: trimmed, nothing else. Case is preserved
    /// because the server stores it verbatim; only the reserved check folds case.
    static func normalized(_ raw: String) -> String {
        raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Strips everything the rule forbids, for live filtering as the user types.
    /// This is what stops a paste of `alice; DROP` or `../../admin` from ever
    /// reaching the field, let alone the wire.
    static func sanitized(_ raw: String) -> String {
        String(normalized(raw).prefix(maxLength).filter(isAllowed))
    }

    /// `nil` when the name is acceptable; otherwise the reason, phrased for a
    /// user rather than a log.
    static func rejectionReason(_ raw: String) -> String? {
        let name = normalized(raw)
        if name.isEmpty { return "pick a username" }
        if name.count < minLength { return "at least \(minLength) characters" }
        if name.count > maxLength { return "at most \(maxLength) characters" }
        if !name.allSatisfy(isAllowed) { return "letters, numbers and _ only" }
        if reserved.contains(name.lowercased()) { return "that username is reserved" }
        return nil
    }

    static func isValid(_ raw: String) -> Bool { rejectionReason(raw) == nil }

    private static func isAllowed(_ c: Character) -> Bool {
        c.isASCII && (c.isLetter || c.isNumber || c == "_")
    }
}
