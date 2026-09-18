//
//  Redaction.swift
//  DissQus
//
//  The PII / secret scrubber, with no Sentry in it.
//
//  WHY THIS IS ITS OWN FILE. These rules are one half of a pair: the other is
//  services/server/lib/scrub.ts, and both files carry a comment saying they must
//  stay in step. A divergence is not cosmetic — it means an event redacted on one
//  platform ships the same secret in the clear from the other, which for a
//  messenger whose server never sees plaintext is the whole product failing at
//  the observability layer.
//
//  A claim like that should be tested, and it could not be. This code lived in
//  Observability.swift, which imports Sentry unconditionally, so no `swiftc` test
//  slice could compile it and no fuzzer could point at it. Nothing here needs
//  Sentry: it is regexes over strings and a walk over a dictionary. Splitting it
//  out is what makes tests/RedactionTests.swift and the scrub differential fuzzer
//  possible; Observability.swift keeps the two `scrub(Event)`/`scrub(Breadcrumb)`
//  adapters that genuinely do need the SDK.
//
//  Keep in sync with services/server/lib/scrub.ts.
//

import Foundation

enum Redaction {

    // Ordered redactors, most-specific → least-specific, mirroring the server's
    // lib/scrub.ts so an event looks the same whichever side reports it. Each
    // replaces a sensitive shape with a typed placeholder. Best-effort defence:
    // prefer not logging a secret over relying on this, but this is the net for
    // when an unexpected error string or SDK breadcrumb carries one.
    static let redactors: [(NSRegularExpression, String)] = {
        // Compile a redactor, SKIPPING (never crashing) if the pattern is somehow
        // invalid under ICU — a bad rule must not take the whole app down at
        // launch. NSRegularExpression uses ICU, which is stricter than JS regex:
        // e.g. a literal `[` inside a character class must be escaped (`\[`).
        // Mirror the server's lib/scrub.ts shapes but keep them ICU-valid.
        func re(_ p: String, _ template: String) -> (NSRegularExpression, String)? {
            guard let r = try? NSRegularExpression(pattern: p, options: [.caseInsensitive]) else {
                #if DEBUG
                print("⚠️ Redaction: skipping invalid redactor pattern: \(p)")
                #endif
                return nil
            }
            return (r, template)
        }
        // PORTABILITY: no \b and no \s anywhere below, deliberately.
        //
        // Both are engine-defined, and this rule set is mirrored in the server's
        // lib/scrub.ts, which runs on V8 rather than ICU:
        //
        //   \b  JS defines word characters as [A-Za-z0-9_]; ICU uses the Unicode
        //       property. "𝔘t=1614556800,v1=…" has a boundary before `t` in JS
        //       and none in ICU, so the Stripe-signature rule fired on the
        //       server and not here.
        //   \s  JS includes U+FEFF; ICU does not, so [^\s…] consumed a different
        //       span on each side.
        //
        // Spelled out as explicit ASCII classes, the two engines agree by
        // construction rather than by coincidence. Found by
        // services/server/test/fuzz/scrub-differential.ts.
        let wb0 = "(?<![A-Za-z0-9_])"   // start-of-word boundary, ASCII
        let wb1 = "(?![A-Za-z0-9_])"    // end-of-word boundary, ASCII
        let ws  = " \\t\\n\\r\\f\\x0B"  // ASCII whitespace, inside a class

        return [
            // JWTs (three base64url segments) — before the generic base64 rule.
            re("\(wb0)eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\(wb1)", "[jwt]"),
            // Credentials in a URL's userinfo (redis://:pw@host, etc). Keep scheme+host.
            re("\(wb0)([a-z][a-z0-9+.-]*://)[^/\(ws):@]*:[^/\(ws)@]+@", "$1[redacted]@"),
            // key/value secrets: token=…, secret: …, authorization …, password=…
            // Group 3 captures an opening quote so the matching close goes too.
            re("\(wb0)(authorization|auth|bearer|token|secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|dsn|cookie|session|stripe[_-]?signature|signature)\(wb1)([\(ws)]*[:=][\(ws)]*|[\(ws)]+)(\"?)[^\(ws),;\"'}]+\\3", "$1=[redacted]"),
            // Stripe secrets / publishable keys (bodies contain underscores).
            re("\(wb0)(?:sk|rk|whsec|pk)_[A-Za-z0-9_]{10,}\(wb1)", "[stripe-key]"),
            // Stripe webhook signature header (t=…,v1=…). Kept in sync with the
            // server's lib/scrub.ts [stripe-sig] rule — see the sync note there.
            re("\(wb0)t=\\d{10},v1=[a-f0-9]{16,}\(wb1)", "[stripe-sig]"),
            // Emails.
            re("\(wb0)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\(wb1)", "[email]"),
            // IPv6 (compressed + full 8-group) then IPv4.
            // // ReDoS FIX. The previous compressed-IPv6 rule was
            //   (?:[A-Fa-f0-9]{1,4}:)*[A-Fa-f0-9]{0,4}::(?:[A-Fa-f0-9]{1,4}:?)*[A-Fa-f0-9]{0,4}
            // and the `:?` made the colon OPTIONAL, so a run of hex after `::` could be
            // partitioned exponentially many ways. "fe80::" + 64 hex chars + a letter (the
            // letter fails the closing boundary, forcing every partition to be tried) does
            // not terminate — measured at over ten minutes before being killed, on both
            // engines. Every Sentry message, breadcrumb and exception string goes through
            // here, so an attacker-influenced string reaching a log line hangs the process.
            // Each side of `::` is now a colon-separated list with exactly one colon
            // between groups: unambiguous, and linear. Found by scrub-differential.ts.
            re("\(wb0)(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?::(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?\(wb1)", "[ip]"),
            re("\(wb0)(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\(wb1)", "[ip]"),
            re("\(wb0)(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\(wb1)", "[ip]"),
            // Public keys / secret keys / ciphertext: long hex (≥32) or base64 (≥40).
            re("\(wb0)[A-Fa-f0-9]{32,}\(wb1)", "[key]"),
            re("\(wb0)[A-Za-z0-9+/]{40,}={0,2}\(wb1)", "[blob]"),
            // @usernames — a handle maps 1:1 to a person here.
            re("(^|[\(ws)(\\[{:,'\"])@[A-Za-z0-9_]{2,32}\(wb1)", "$1@[user]"),
        ].compactMap { $0 }
    }()

    /// Redact known-sensitive shapes from a single string.
    /// Cap on how much of one string is scanned. Mirrors MAX_STRING in
    /// lib/scrub.ts — a runaway input must not make scrubbing the thing that
    /// stalls, and both sides must stall at the same point.
    static let maxString = 8192

    static func redact(_ input: String?) -> String? {
        guard let input, !input.isEmpty else { return input }
        // Cap the blast radius of a pathological input.
        // Capped in UNICODE SCALARS, matching lib/scrub.ts.
        //
        // `.count` is GRAPHEME CLUSTERS and JS's `.length` is UTF-16 code units,
        // so "𝔘" is 1 here and 2 there and a long string was cut in a different
        // place on each side. Scalars are the one unit both languages count and
        // cut the same way — slicing UTF-16 could split a surrogate pair, which
        // a Swift String cannot represent at all.
        let scalars = input.unicodeScalars
        var s = scalars.count > maxString
            ? String(String.UnicodeScalarView(scalars.prefix(maxString))) + "…[truncated]"
            : input
        for (re, template) in redactors {
            let range = NSRange(s.startIndex..., in: s)
            s = re.stringByReplacingMatches(in: s, options: [], range: range, withTemplate: template)
        }
        return s
    }

    /// Deep-scrub an arbitrary [String: Any] bag (extra / breadcrumb data):
    /// redact strings and drop values under sensitive-named keys. Word-aware
    /// (not substring) so "recipient"/"description" don't trip on "ip"/"sig" —
    /// mirrors isSensitiveKey() in the server's lib/scrub.ts.
    static let sensitiveWords: Set<String> = [
        "authorization", "auth", "bearer", "cookie", "token", "secret", "password",
        "passwd", "pwd", "apikey", "dsn", "session", "signature", "sig", "credential",
        "credentials", "pubkey", "payload", "ciphertext", "nonce", "ip",
    ]
    static let sensitivePhrases = [
        "publickey", "privatekey", "apikey", "accesskey", "secretkey",
        "ipaddress", "remoteaddress", "xforwardedfor",
    ]
    static func isSensitive(_ key: String) -> Bool {
        // Split camelCase, then snake/kebab/space, into lowercase words.
        let spaced = key.replacingOccurrences(
            of: "([a-z0-9])([A-Z])", with: "$1 $2",
            options: .regularExpression
        )
        // Split on anything outside [A-Za-z0-9] — matching lib/scrub.ts's
        // `.split(/[^A-Za-z0-9]+/)` exactly, including its treatment of
        // non-ASCII letters as SEPARATORS.
        //
        // `isLetter` is the intuitive choice and it is the wrong one here. It is
        // true for é, so Swift read "tokenÜ" as the single word "tokenü" and
        // called it insensitive, while the server split it to ["token"] and
        // redacted. The client is the side that holds plaintext, so the platform
        // under-redacting was the one it costs most on. Found by
        // test/fuzz/scrub-differential.ts --mode key.
        //
        // Where the two could differ, the safer direction is to split MORE: an
        // extra split can only expose more whole words to the sensitive list.
        let words = spaced.lowercased()
            .split { !$0.isASCII || (!$0.isLetter && !$0.isNumber) }
            .map(String.init)
        if words.contains(where: { sensitiveWords.contains($0) }) { return true }
        let glued = words.joined()
        return sensitivePhrases.contains { glued.contains($0) }
    }
    static func scrubDeep(_ value: Any, depth: Int = 0) -> Any {
        if depth > 6 { return "[max-depth]" }
        switch value {
        case let s as String: return redact(s) ?? s
        case let arr as [Any]: return arr.map { scrubDeep($0, depth: depth + 1) }
        case let dict as [String: Any]:
            var out: [String: Any] = [:]
            for (k, v) in dict { out[k] = isSensitive(k) ? "[redacted]" : scrubDeep(v, depth: depth + 1) }
            return out
        default: return value
        }
    }
}
