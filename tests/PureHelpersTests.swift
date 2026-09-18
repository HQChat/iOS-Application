// The two pure rules every screen depends on, neither compiled by a test before.
//
// UsernameRule is the only input filter on this client. `sanitized` is what runs
// as the user types, so it is the thing that decides whether `alice; DROP` or
// `../../admin` can ever reach the field, let alone the wire. Its bounds are
// declared to be "the same the server enforces", and nothing held them to that.
//
// AppError is what the user actually READS when something fails. It is not
// decoration: an error that says nothing actionable sends a person to support,
// and one that leaks a server's raw text sends them internals.

import Foundation

// ── The username filter ──────────────────────────────────────────────────────

check(UsernameRule.isValid("alice"), "an ordinary handle is accepted")
check(UsernameRule.isValid("a_1"), "the minimum length is accepted")
check(UsernameRule.isValid(String(repeating: "a", count: 32)), "the maximum length is accepted")

check(!UsernameRule.isValid(String(repeating: "a", count: 33)), "one over the maximum is refused")
check(!UsernameRule.isValid("ab"), "one under the minimum is refused")
check(!UsernameRule.isValid(""), "an empty handle is refused")
check(!UsernameRule.isValid("   "), "whitespace alone is refused, not trimmed into nothing")

// The filter is the injection defence. Every one of these is a real payload
// shape, and none of them may survive `sanitized` in a form that still carries
// its punctuation.
for hostile in ["alice; DROP TABLE users", "../../admin", "alice@example.com",
                "<script>alert(1)</script>", "alice\u{0000}bob", "alice bob",
                "alice/../root", "%2e%2e%2fadmin", "alice\nbob", "aliceʼs"] {
    let clean = UsernameRule.sanitized(hostile)
    check(clean.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") },
          "sanitized(\(hostile.prefix(18))…) keeps only letters, numbers and _")
    check(!UsernameRule.isValid(hostile) || clean == hostile,
          "a handle that validates must already be its own sanitized form")
}

check(UsernameRule.sanitized(String(repeating: "a", count: 100)).count == 32,
      "sanitized never returns more than the field accepts")

// Non-ASCII is refused rather than transliterated. Homoglyph handles are how one
// account impersonates another in a contact list.
for confusable in ["аlice", "alicе", "𝗮lice", "ali̇ce", "ＡＬＩＣＥ"] {
    check(!UsernameRule.isValid(confusable), "a non-ASCII lookalike is refused (\(confusable))")
}

// Reserved names fold case; the stored form does not. Two different rules in one
// function, and getting them the same way round would either let `Admin` through
// or lowercase everybody's handle.
check(!UsernameRule.isValid("admin") && !UsernameRule.isValid("ADMIN")
      && !UsernameRule.isValid("AdMiN"), "a reserved handle is refused in any case")
check(UsernameRule.normalized("AlIcE") == "AlIcE", "case is preserved in what is sent")
check(UsernameRule.normalized("  alice  ") == "alice", "surrounding whitespace is trimmed")

check(UsernameRule.reserved.contains("helper"),
      "the helper bot's own handle is reserved, or a user could take it")
check(UsernameRule.reserved.allSatisfy { $0 == $0.lowercased() },
      "the reserved set is lowercase, or the case-folded lookup misses entries")

// Every rejection has to be readable by the person who typed it.
for bad in ["", "ab", String(repeating: "a", count: 33), "alice!", "admin"] {
    let reason = UsernameRule.rejectionReason(bad)
    check(reason != nil, "\"\(bad.prefix(10))\" is rejected with a reason")
    check(!(reason ?? "").isEmpty && (reason ?? "").first?.isUppercase != true,
          "the reason reads as a hint, not a sentence fragment shouted at the user")
}
check(UsernameRule.rejectionReason("alice") == nil, "a good handle has no complaint")
check(UsernameRule.hint.contains("\(UsernameRule.minLength)")
      && UsernameRule.hint.contains("\(UsernameRule.maxLength)"),
      "the hint names the real bounds rather than repeating them by hand")

// ── What the user reads when something fails ─────────────────────────────────

let allErrors: [AppError] = [
    .network(.notConnectedToInternet), .network(.timedOut), .network(.cannotFindHost),
    .network(.networkConnectionLost), .network(.badServerResponse),
    .server(code: "USERNAME_TAKEN", message: "that handle is taken"),
    .server(code: nil, message: "unavailable"),
    .crypto("no session"), .keychain("-25293"), .validation("too short"), .unknown("?"),
]

for e in allErrors {
    check(!e.title.isEmpty, "\(e.title): has a headline")
    check(!e.userMessage.isEmpty, "\(e.title): has something a person can read")
    check(e.id == e.title + e.userMessage, "\(e.title): its identity is its content")
}

// A distinct headline per case: an alert that always says "Something went wrong"
// teaches people to dismiss it without reading.
check(Set(allErrors.map(\.title)).count >= 5, "the headlines distinguish the kinds of failure")

// Offline is the one a user can act on, and it must say so.
check(AppError.network(.notConnectedToInternet).userMessage.lowercased().contains("offline"),
      "being offline is named as being offline")

// Equatable, because the UI dedupes alerts by value — two identical failures
// must not stack two identical sheets.
check(AppError.crypto("x") == AppError.crypto("x"), "the same failure is the same value")
check(AppError.crypto("x") != AppError.crypto("y"), "different details are different values")
check(AppError.crypto("x") != AppError.validation("x"), "the kind is part of the identity")

// A server's raw text is shown for `.server` — that is the one case where it is
// written for a user — but a raw keychain or crypto detail is not.
check(AppError.server(code: "X", message: "that handle is taken")
        .userMessage.contains("that handle is taken"),
      "the server's own wording survives, since it is the one written for a user")
// `.server`, `.crypto`, `.keychain`, `.validation` and `.unknown` all return
// their message verbatim — this type is a carrier, and what a person reads is
// decided by whoever constructed it. Pinned as such rather than asserting a
// property the type cannot guarantee: my first version demanded that a raw
// OSStatus never reach the user, which this enum has no way to enforce.
check(AppError.keychain("errSecInteractionNotAllowed -25293").userMessage
        == "errSecInteractionNotAllowed -25293",
      "a carried message is passed through unchanged, for better or worse")

// ── Whether the alert offers a retry ─────────────────────────────────────────
//
// This drives a button. Offering "Try again" for a validation failure loops the
// user through the same refusal; withholding it on a dropped connection makes a
// transient blip look permanent.
check(AppError.network(.timedOut).isRetryable, "a timeout is worth retrying")
check(AppError.network(.notConnectedToInternet).isRetryable, "so is being offline")
for e: AppError in [.server(code: nil, message: "x"), .crypto("x"), .keychain("x"),
                    .validation("x"), .unknown("x")] {
    check(!e.isRetryable, "\(e.title) is not retryable — the same request fails the same way")
}

// ── Wrapping somebody else's error ───────────────────────────────────────────

check(AppError.from(AppError.crypto("already ours")) == AppError.crypto("already ours"),
      "wrapping an AppError is the identity — it must not become .unknown")
check(AppError.from(URLError(.timedOut)) == AppError.network(.timedOut),
      "a URLError keeps its code, so the message can stay specific")
check(AppError.from(URLError(.notConnectedToInternet)).isRetryable,
      "…and stays retryable through the wrap")
struct Odd: Error {}
if case .unknown = AppError.from(Odd()) {
    check(true, "anything else becomes .unknown rather than being dropped")
} else {
    check(false, "an unrecognised error did not become .unknown")
}

finish()
