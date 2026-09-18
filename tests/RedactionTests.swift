// The scrubber, on the client side.
//
// This is the last thing that runs before an event leaves the device. If it is
// wrong, a messenger whose entire design keeps plaintext away from the server
// hands the same plaintext to a third-party crash reporter — from the one place
// that definitely has it. Worth more than the zero tests it had.
//
// It had zero because it could not have any: this code lived in
// Observability.swift, which imports Sentry, so no swiftc slice could compile it.
// It is Redaction.swift now.
//
// Everything asserted here is also asserted on the server side by
// services/server/test/scrub.test.ts. Where the two disagree, the differential
// fuzzer (test/fuzz/scrub-differential.ts) is what finds it — these are the
// pinned cases, not the search.

import Foundation

func r(_ s: String) -> String { Redaction.redact(s) ?? "" }

print("Textual redactors")

// Ordering matters: the specific high-entropy shapes must run before the broad
// hex/base64 rules, or a token gets chewed in half and the placeholder lies
// about what it replaced.
let jwt = "eyJQTEFDRUhPTERFUn0.eyJQTEFDRUhPTERFUn0.PLACEHOLDERsignature"
check(r(jwt) == "[jwt]", "a JWT is redacted as a jwt, not chewed up by the base64 rule")
check(r("got \(jwt) back") == "got [jwt] back", "…including mid-sentence")

// Rule ordering, pinned because it is surprising and both sides must be
// surprising in the same way: the JWT rule replaces first, and then the
// bearer key/value rule swallows the placeholder it left behind. Still
// redacted, just by the other rule — and the server does exactly this too.
check(r("Bearer \(jwt)") == "Bearer=[redacted]",
      "a Bearer-prefixed JWT is taken by the key/value rule, not the jwt rule")

check(r("postgresql://user:PLACEHOLDER@db.internal:5432/hqcat") == "postgresql://[redacted]@db.internal:5432/hqcat",
      "URL userinfo is dropped, scheme and host kept")

check(r("token=abc123def456") == "token=[redacted]", "a token= pair is redacted")
check(r("Authorization: Bearer sk_test_PLACEHOLDER02").contains("[redacted]"),
      "an authorization header is redacted")

check(r("charge failed for sk_test_PLACEHOLDER01") == "charge failed for [stripe-key]",
      "a Stripe secret key is redacted")
check(r("t=1614556800,v1=5257a869e7ecebeda32affa62cdca3fa") == "[stripe-sig]",
      "a Stripe webhook signature is redacted")

check(r("mail to alice@example.com failed") == "mail to [email] failed", "an email is redacted")

print("")
print("Addresses — PII for an E2EE messenger")

check(r("from 192.168.1.254") == "from [ip]", "IPv4 is redacted")
check(r("from 2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "from [ip]", "full IPv6 is redacted")
check(r("from fe80::1") == "from [ip]", "compressed IPv6 is redacted")

// The 8-group rule needs seven colons precisely so it cannot eat a timestamp.
check(!r("elapsed 12:34:56").contains("[ip]"), "a clock time is not mistaken for an address")

print("")
print("Keys and handles")

check(r("pk 4f3c2b1a4f3c2b1a4f3c2b1a4f3c2b1a") == "pk [key]", "long hex is redacted as a key")
check(r("@alice_k said hi") == "@[user] said hi", "a handle is redacted")
check(r("email me at a@b.co") == "email me at [email]",
      "an email still wins over the handle rule")

// Not everything long is a secret, and over-redaction destroys the diagnostic
// value the event was collected for.
check(r("order 12345 failed") == "order 12345 failed", "a short number is left alone")
check(r("connection reset by peer") == "connection reset by peer", "ordinary prose is untouched")

print("")
print("Bounds")

// A pathological input must not turn scrubbing into the thing that stalls.
let long = String(repeating: "a", count: 9000)
check((Redaction.redact(long) ?? "").hasSuffix("…[truncated]"), "an over-long string is truncated")
check(Redaction.redact("") == "", "an empty string is returned unchanged")
check(Redaction.redact(nil) == nil, "nil is returned unchanged")

// Running it twice must not keep rewriting its own placeholders.
let once = r("token=abc123def456 from 10.0.0.1")
check(r(once) == once, "redaction is idempotent")

// A fuzz finding, pinned. The compressed-IPv6 rule used to make the colon after
// each hex group optional, so a run of hex after "::" could be split into groups
// exponentially many ways. The trailing letter is load-bearing: it fails the
// closing word boundary, which forces the engine to try every one of them. This
// input did not terminate in ten minutes on either engine, and every Sentry
// message and breadcrumb goes through redact() — so a string like this reaching
// a log line hangs the app.
//
// Found by services/server/test/fuzz/scrub-differential.ts. The fuzz run is
// occasional; this runs every time.
let redos = "fe80::1" + String(repeating: "a", count: 64) + "token"
let redosStart = Date()
_ = Redaction.redact(redos)
check(Date().timeIntervalSince(redosStart) < 1.0,
      "the compressed-IPv6 rule does not backtrack exponentially")

print("")
print("Sensitive keys — the value goes regardless of shape")

func deep(_ v: Any) -> [String: Any] { Redaction.scrubDeep(v) as? [String: Any] ?? [:] }

let bag = deep([
    "publicKey": "not-obviously-a-key",
    "sessionToken": "abc",
    "ipAddress": "n/a",
    "ciphertext": "xyz",
    // The word-aware split is the whole point: substring matching would redact
    // every one of these, and an event whose fields are all "[redacted]" is not
    // an event.
    "recipient": "bob",
    "description": "a note",
    "tripped": "yes",
    "signal": "green",
])
check(bag["publicKey"] as? String == "[redacted]", "publicKey is dropped by name")
check(bag["sessionToken"] as? String == "[redacted]", "sessionToken is dropped by name")
check(bag["ipAddress"] as? String == "[redacted]", "ipAddress is dropped by name")
check(bag["ciphertext"] as? String == "[redacted]", "ciphertext is dropped by name")
check(bag["recipient"] as? String == "bob", "…but 'recipient' does not trip on 'ip'")
check(bag["description"] as? String == "a note", "…nor 'description' on 'sig'")
check(bag["tripped"] as? String == "yes", "…nor 'tripped' on 'ip'")
check(bag["signal"] as? String == "green", "…nor 'signal' on 'sig'")

print("")
print("Deep structures")

let nested = deep(["outer": ["inner": ["note": "reach me at a@b.com"]]])
let outer = nested["outer"] as? [String: Any] ?? [:]
let inner = outer["inner"] as? [String: Any] ?? [:]
check(inner["note"] as? String == "reach me at [email]", "strings are redacted at depth")

let arr = Redaction.scrubDeep(["a@b.com", "1.2.3.4"]) as? [Any] ?? []
check(arr.first as? String == "[email]", "strings inside arrays are redacted")

// Depth is bounded so a cyclic-ish or runaway structure cannot stall the walk.
var deepValue: Any = "a@b.com"
for _ in 0..<10 { deepValue = ["k": deepValue] }
var walk = Redaction.scrubDeep(deepValue)
var levels = 0
while let d = walk as? [String: Any], let next = d["k"] { walk = next; levels += 1 }
check(walk as? String == "[max-depth]", "the walk stops at the depth cap")
check(levels <= 7, "…and stops there, rather than descending forever")

finish()
