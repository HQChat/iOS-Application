#!/usr/bin/env bash
#
# verify.sh — the full Apple gate, run locally.
#
# This used to be a `macos-15` job in .github/workflows/ci.yml. It ran on every
# push to main and preprod (the reusable-workflow path forced it even for
# server-only changes), and at the 10x macOS billing multiplier with per-job
# minute round-up it was 84% of the repo's entire GitHub Actions bill — 2,400 of
# 2,850 billable minutes in August 2026, for 155 minutes of actual work. It was
# removed; this script is where that coverage went.
#
# Run it before merging anything under apps/apple/, and before a release:
#
#   bash apps/apple/verify.sh
#
# Unlike the old CI job it shares one DerivedData directory across the xcodebuild
# invocations, so the iOS app is compiled once for the device slice and once for
# the simulator slice instead of three times from cold.
set -euo pipefail

cd "$(dirname "$0")"

DERIVED="${DERIVED_DATA_PATH:-$PWD/.build/DerivedData}"
SIM_NAME="${SIM_NAME:-iPhone 16 Pro}"
mkdir -p "$DERIVED"

command -v xcodebuild >/dev/null || {
  echo "❌ xcodebuild not found — this script needs Xcode and only runs on macOS." >&2
  exit 1
}

step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

# 0. The C wrapper underneath everything else.
#
#    Swift and Node both sit on this library, and until now nothing ran its test:
#    test.sh was referenced by no job and no doc, its main.c had not compiled
#    since the IND-CCA2 migration removed the PKE wrappers it called, and its
#    main() returned 0 even when it printed a mismatch. Running it first means a
#    broken KEM is reported as a broken KEM, rather than as thirty confusing
#    Swift failures further down.
step "Native HQC wrapper (C)"
bash ../../native/hqc/test/test.sh

# 1. The pure-Swift suites (crypto, ratchet, key fingerprint, MQTT wire codec,
#    message-at-rest). These compile the real implementations, not copies.
#
#    A suite that SKIPS a check now fails unless tests/expected-skips.txt budgets
#    it: six checks cannot run in an unsigned local build (Secure Enclave and the
#    keychain access group), and they used to pass silently.
step "Swift tests (crypto / ratchet / codec)"
COVERAGE=1 bash tests/run.sh

# The number that says how much of the app those suites actually reach.
#
# There is no Xcode unit-test target here, so `-enableCodeCoverage` has nothing
# to attach to — but swiftc takes the instrumentation flags directly, so the
# compile lists in tests/run.sh stay the single source of truth and still produce
# per-file coverage. NO THRESHOLD YET: this establishes the baseline, and the
# gate goes on once the number is somewhere worth defending.
step "Swift coverage"
bash tests/coverage-report.sh

# 2. macOS app builds. No signing: this proves the target compiles, nothing more.
step "Build macOS"
xcodebuild -scheme DissQus -destination 'platform=macOS' \
  -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  -quiet build

# 3. iOS app builds for a real device slice.
step "Build iOS (device)"
xcodebuild -scheme 'DissQus iOS' -destination 'generic/platform=iOS' \
  -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  -quiet build

# 4. UI tests on the simulator. Split into build-for-testing + test-without-
#    building so the compile is visible separately from the (flakier) run, and
#    so a rerun of just the tests doesn't recompile.
step "Build for testing (iOS simulator)"
xcodebuild -scheme 'DissQus iOS' -destination "platform=iOS Simulator,name=$SIM_NAME" \
  -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  -quiet build-for-testing

#     TEST_RUNNER_HQCAT_UNSIGNED tells the UI bundle what this invocation
#     already knows: CODE_SIGNING_ALLOWED=NO, so the app has no keychain access
#     group and SecKeyCreateRandomKey fails with -34018 errSecMissingEntitlement.
#     Two tests depend on that key and skip on it (MAS-9). xcodebuild strips the
#     TEST_RUNNER_ prefix on the way into the test process.
#
#     Declared rather than detected on purpose. The first attempt asked the test
#     process `SecureEnclave.isAvailable`, which is TRUE on a modern Simulator
#     and answers the wrong question twice over — the blocker is signing, not the
#     Enclave, and XCUITest runs in a different process from the app whose
#     entitlements actually decide it. A signed device run simply does not set
#     this, and the two tests run.
step "UI tests (iOS simulator: $SIM_NAME)"
TEST_RUNNER_HQCAT_UNSIGNED=1 \
xcodebuild -scheme 'DissQus iOS' -destination "platform=iOS Simulator,name=$SIM_NAME" \
  -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  -quiet test-without-building

# 4b. The two targets that need no TypeScript half.
#
#     `topic-route` is `MQTTTopics.route` on attacker-supplied strings — every
#     inbound publish carries a topic the sender chose, and route decides which
#     conversation the payload belongs to before anything authenticates who sent
#     it. `scrub-verdict` is built here rather than run, because its driver lives
#     on the TypeScript side (step 5b).
step "Topic routing fuzz"
bash fuzz/run.sh topic-route --iterations "${FUZZ_TOPIC_ITERATIONS:-50000}" --seed "${FUZZ_SEED:-$RANDOM}"

#     `n` and `pn` arrive on a frame header and are read to CHOOSE the message
#     key, so they cannot have been authenticated by the payload that key opens.
#     A gap walked before it is bounded is an HKDF per step — two billion of them
#     at n = 2^31, on the MainActor.
step "Ratchet state fuzz"
bash fuzz/run.sh ratchet-state --iterations "${FUZZ_RATCHET_ITERATIONS:-10000}" --seed "${FUZZ_SEED:-$RANDOM}"

# 5. Cross-implementation frame fuzzing.
#
#    This is the check CI cannot run. `ConversationEnvelopeV3.decodeReporting`
#    and services/server/lib/envelope-v3.ts `decodeV3` are meant to be the SAME
#    predicate over the same bytes, and a divergence there is invisible to either
#    suite alone: each one passes, and a frame written by one end is silently
#    dropped by the other. That is the bug class that broke every e2e
#    conversation once already, back when the pair was v2's.
#
#    Three oracles rather than two: verdict, AAD, and the DECODED FIELDS. The
#    format reads integers out of byte offsets instead of out of a parsed object,
#    so "both accepted, same AAD, different `n`" is reachable in a way it was not
#    in JSON — and it would be a frame-confusion bug, not a cosmetic one. The AAD
#    one matters most: a divergence there surfaces as a GCM tag mismatch,
#    indistinguishable from a wrong key.
#
#    Seeded from the shared vectors both suites already assert, then mutated.
#    A finding is written to services/server/test/fuzz/findings/.
#
#    Fewer iterations by default than the v2 harness this replaced, and
#    deliberately: a frame carries up to 58 kB of KEM material, so this runs at a
#    few hundred per second. The mutations are aimed at the header, which is
#    where all the offsets are, so the low count still covers the surface.
step "Frame differential fuzz (Swift ↔ TypeScript)"
bash fuzz/run.sh envelope-v3-verdict
(cd ../../services/server && npx tsx test/fuzz/envelope-v3-differential.ts \
   --iterations "${FUZZ_V3_ITERATIONS:-5000}" --seed "${FUZZ_SEED:-$RANDOM}")

# 7. The same two implementations, from the other end.
#
#    Everything above tests DECODERS. The encoders were the half nobody had
#    pointed a fuzzer at, and they disagreed on every malformed input, because
#    they fail in structurally different ways: TypeScript copies into a fixed
#    buffer (short pads, long clips), Swift appends (a wrong length shifts every
#    field after it), and writeUInt32BE throws where truncatingIfNeeded wraps.
#
#    Structs in, frames out: both must refuse the same ones and produce
#    byte-identical bytes for the rest. Faster than the decode driver — a
#    generator, no mutation corpus — so the default count is higher.
step "Envelope v3 ENCODE differential fuzz (Swift ↔ TypeScript)"
bash fuzz/run.sh envelope-v3-encode-verdict
(cd ../../services/server && npx tsx test/fuzz/envelope-v3-encode-differential.ts \
   --iterations "${FUZZ_V3_ENCODE_ITERATIONS:-20000}" --seed "${FUZZ_SEED:-$RANDOM}")

# 7b. The scrubber, against its TypeScript twin.
#
#     lib/scrub.ts and Redaction.swift are one rule set maintained twice, and
#     each file asks the next person to keep them in step. This is what checks
#     whether anyone did. It has already found a ReDoS that hung both engines and
#     a key-name split that made the CLIENT — the side holding plaintext — redact
#     less than the server.
step "Scrubber differential fuzz (Swift ↔ TypeScript)"
bash fuzz/run.sh scrub-verdict
(cd ../../services/server && \
  npx tsx test/fuzz/scrub-differential.ts \
    --iterations "${FUZZ_SCRUB_ITERATIONS:-20000}" --seed "${FUZZ_SEED:-$RANDOM}" --mode redact && \
  npx tsx test/fuzz/scrub-differential.ts \
    --iterations "${FUZZ_SCRUB_ITERATIONS:-20000}" --seed "${FUZZ_SEED:-$RANDOM}" --mode key)

# 7c. The handshake frame, both directions.
#
#     h/{friendshipHash} carries what closes the impersonation gap an init leaves
#     open, and both ends parse it with hand-written offset arithmetic. Until this
#     existed the only thing comparing them was five pinned vectors they agree on
#     by construction.
#
#     Three modes: decode (bytes in), encode (frames in — the half the envelope
#     work found diverging on every malformed input while the decoders agreed),
#     and round, which checks each side is its own inverse.
step "Handshake differential fuzz (Swift ↔ TypeScript)"
bash fuzz/run.sh handshake-verdict
(cd ../../services/server && \
  for m in decode encode round; do \
    npx tsx test/fuzz/handshake-differential.ts \
      --iterations "${FUZZ_HANDSHAKE_ITERATIONS:-20000}" --seed "${FUZZ_SEED:-$RANDOM}" --mode "$m" || exit 1; \
  done)

# 8. A whole interaction, through the real Swift implementation.
#
#    Everything above tests a layer at a time. This runs first contact to a
#    verified transcript — friend request, prekey claim, init, the
#    initiator-authentication handshake, five messages each way, replay refusal —
#    over a bus made of files, with the REAL HQC library linked rather than a
#    stub. It is the only Swift test that exercises the protocol as a whole.
#
#    It used to run TWICE, once per wire version, because that was the frame
#    seam's claim: above the transport, the version was only a spelling. The
#    claim held — nothing above the seam changed when v2 was deleted — and there
#    is one run now.
step "End-to-end (file bus, real HQC)"
bash e2e/run.sh

# 9. The same script over a channel that misbehaves.
#
#    Nothing above is interesting over a perfect channel: the ratchet's
#    skipped-key cache and the replay refusal are only reachable when delivery
#    duplicates or reorders, and MQTT at QoS 1 promises at LEAST once, so a
#    redelivery is ordinary rather than exotic. Seeded, so a failure replays.
#
#    The run asserts that the channel actually misbehaved — a fault injector that
#    injects nothing reports the same green as a clean run.
step "End-to-end over a lossy channel"
bash e2e/run.sh --faults --seed "${FUZZ_SEED:-$RANDOM}"

# Record WHAT was verified, so a push can check it.
#
# This gate is local by choice — a macOS runner was 84% of this repo's Actions
# bill — and a local gate only works if it is actually run. The stamp is what
# makes "I ran verify.sh" checkable instead of a claim: apps/apple/hooks/pre-push
# reads it and refuses to push Apple changes it does not cover.
#
# A dirty tree stamps as dirty rather than as HEAD. Verifying uncommitted work
# says nothing about the commit that gets pushed, and quietly pretending
# otherwise is the failure mode this is meant to remove.
mkdir -p .build
if [ -z "$(git status --porcelain -- . 2>/dev/null)" ]; then
  git rev-parse HEAD > .build/verify-stamp
else
  echo "dirty" > .build/verify-stamp
fi

printf '\n\033[1;32m✅ Apple verification passed\033[0m\n'
printf '   stamped %s\n' "$(cat .build/verify-stamp)"
