#!/usr/bin/env bash
#
# Compiles selected app source files together with the Swift test files and
# runs them. Tests the real implementations (no copies) without needing an
# Xcode test target. Used by CI and runnable locally: `bash apple/tests/run.sh`
#
set -euo pipefail

cd "$(dirname "$0")"
SRC="../DissQus/Services"
MODELS="../DissQus/Models"
HELPERS="../DissQus/Helpers"
APP="../DissQus"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- Skip census -------------------------------------------------------------
# A skipped check is coverage that left. `finish()` used to warn and exit 0, so a
# guarantee could stop being tested while the gate stayed green. expected-skips.txt
# says how many skips each suite is allowed; a suite with no line gets zero, and
# exceeding the allowance fails the run. See TestSupport.swift.
CENSUS="$PWD/expected-skips.txt"
expected_skips() {
  # Tab-separated: <suite> <count> <reason>. Missing suite -> 0.
  awk -v s="$1" -F'\t' '$1 == s { print $2; found = 1 } END { if (!found) print 0 }' "$CENSUS"
}

# --- Coverage (opt-in) -------------------------------------------------------
# COVERAGE=1 builds every slice with source-based coverage instrumentation and
# writes a per-file report at the end.
#
# WHY NOT AN XCODE TEST TARGET. `xcodebuild test -enableCodeCoverage YES` needs a
# unit-test bundle, and this project has none — the suites are compiled here by
# swiftc from explicit source lists. Adding a target would mean maintaining those
# lists twice, in a .pbxproj, which is exactly the duplication that broke this
# script silently once before. swiftc takes the same instrumentation flags
# directly, so the compile lists below stay the single source of truth.
#
#   COVERAGE=1 bash tests/run.sh
#
# shellcheck disable=SC2086  # COV_FLAGS is deliberately word-split
COVERAGE="${COVERAGE:-0}"
COV_FLAGS=""
BINDIR="$TMP"

# Each slice stages its test file as main.swift (Swift requires top-level code to
# live there). Give every slice its OWN directory: sharing one path made
# llvm-profdata see conflicting records for `main.swift:main` and warn
# "counter mismatch" on every merge, which would hide a real one.
# Staged under $TMP/stage/, NOT $TMP/ — macOS is case-insensitive by default, so
# a staging dir named CryptoTests collides with the binary cryptoTests and the
# linker fails with "Is a directory". Only bites when COVERAGE is unset, because
# the binaries move to .coverage/bin when it is set.
stage() {  # stage <TestFile.swift> -> prints the staged main.swift path
  local d="$TMP/stage/${1%.swift}"
  mkdir -p "$d"
  cp "$1" "$d/main.swift"
  echo "$d/main.swift"
}
if [ "$COVERAGE" = "1" ]; then
  COV_DIR="${COV_DIR:-$PWD/.coverage}"
  rm -rf "$COV_DIR"
  mkdir -p "$COV_DIR/bin"
  BINDIR="$COV_DIR/bin"
  COV_FLAGS="-profile-generate -profile-coverage-mapping"
  # %m expands to a per-binary signature, so each slice writes its own raw
  # profile without any per-invocation plumbing.
  export LLVM_PROFILE_FILE="$COV_DIR/%m.profraw"
fi

# Top-level test code must live in a file named main.swift when compiling
# multiple files, so each test file is copied there before building.
#
# Every slice must list the FULL transitive source set — there is no target here
# to resolve it. A call added to an app file that this script compiles must have
# its own file added below, or the slice stops compiling. That is how the whole
# suite broke silently when BiometricAudit was introduced: CI does not build the
# Apple apps, so nothing failed until someone ran this.
echo "── Crypto tests ───────────────────────────────"
MAIN="$(stage CryptoTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift Stubs.swift \
  "$SRC/AESService.swift" "$SRC/BiometricAudit.swift" \
  -o "$BINDIR/cryptoTests"
"$BINDIR/cryptoTests"

echo ""
echo ""
echo "── Key fingerprint tests ──────────────────────"
MAIN="$(stage KeyFingerprintTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/KeyFingerprint.swift" \
  -o "$BINDIR/keyFingerprintTests"
"$BINDIR/keyFingerprintTests"

echo ""
echo "── Client identifier (cross-impl vectors) ─────"
# `id = sha256(lowercase-hex(pk))` is the name every other layer keys on. Four
# implementations must agree — this one, lib/identity.ts, Postgres's pk_digest,
# and the EMQX authorizer query — so the vectors are READ rather than pasted in.
ID_VECTORS="../../../services/server/test/helpers/identity-vectors.json"
if [ ! -f "$ID_VECTORS" ]; then
  echo "❌ missing $ID_VECTORS — regenerate with:"
  echo "   npx tsx scripts/gen-identity-vectors.ts > test/helpers/identity-vectors.json"
  exit 1
fi
MAIN="$(stage PeerIDTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/PeerID.swift" \
  -o "$BINDIR/peerIdTests"
"$BINDIR/peerIdTests" "$(cd "$(dirname "$ID_VECTORS")" && pwd)/$(basename "$ID_VECTORS")"

echo ""
echo "── MQTT topic routing tests ───────────────────"
MAIN="$(stage MQTTTopicsTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" \
  "$SRC/MQTTTopics.swift" "$SRC/PeerID.swift" \
  -o "$BINDIR/mqttTopicsTests"
"$BINDIR/mqttTopicsTests"

echo ""
echo "── MQTT wire codec tests ──────────────────────"
MAIN="$(stage MQTTWireTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift Stubs.swift \
  "$SRC/MQTTWireClient.swift" \
  -o "$BINDIR/mqttWireTests"
"$BINDIR/mqttWireTests"

echo ""
echo "── Double ratchet v2 (cross-impl vectors) ─────"
# The vectors are READ, not copied into the Swift source: the v1 test pasted the
# hex in, so a change on the TypeScript side left this one asserting stale values
# and passing. The path is passed in so a missing file fails loudly.
VECTORS="../../../services/server/test/helpers/double-ratchet-vectors.json"
if [ ! -f "$VECTORS" ]; then
  echo "❌ missing $VECTORS — regenerate with:"
  echo "   npx tsx scripts/gen-ratchet-vectors.ts > test/helpers/double-ratchet-vectors.json"
  exit 1
fi
MAIN="$(stage DoubleRatchetTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/DoubleRatchet.swift" \
  -o "$BINDIR/doubleRatchetTests"
"$BINDIR/doubleRatchetTests" "$(cd "$(dirname "$VECTORS")" && pwd)/$(basename "$VECTORS")"

echo ""
echo "── Ratchet session (state machine) ────────────"
# Stub KEM, so the state machine is exercised without linking the native HQC
# library. Mirrors services/server/test/ratchet-session.test.ts: the two have to
# agree on BEHAVIOUR, not just on KDF output.
MAIN="$(stage RatchetSessionTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/DoubleRatchet.swift" "$SRC/RatchetSession.swift" \
  -o "$BINDIR/ratchetSessionTests"
"$BINDIR/ratchetSessionTests"

echo ""
echo "── Handshake proof (cross-impl) ───────────────"
HS_VECTORS="../../../services/server/test/helpers/handshake-vectors.json"
if [ ! -f "$HS_VECTORS" ]; then
  echo "❌ missing $HS_VECTORS — regenerate with:"
  echo "   npx tsx scripts/gen-handshake-vectors.ts > test/helpers/handshake-vectors.json"
  exit 1
fi
MAIN="$(stage HandshakeTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/Handshake.swift" \
  -o "$BINDIR/handshakeTests"
"$BINDIR/handshakeTests" "$HS_VECTORS"

echo ""
echo "── Envelope v3 (binary framing, cross-impl) ───"
V3_VECTORS="../../../services/server/test/helpers/envelope-v3-vectors.json"
if [ ! -f "$V3_VECTORS" ]; then
  echo "❌ missing $V3_VECTORS — regenerate with:"
  echo "   npx tsx scripts/gen-envelope-v3-vectors.ts > test/helpers/envelope-v3-vectors.json"
  exit 1
fi
MAIN="$(stage EnvelopeV3Tests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/ConversationEnvelopeV3.swift" "$SRC/PeerID.swift" \
  -o "$BINDIR/envelopeV3Tests"
"$BINDIR/envelopeV3Tests" "$V3_VECTORS"

echo ""
echo "── Redaction (the Sentry scrubber) ────────────"
# The last thing that runs before an event leaves the device. A miss here sends
# plaintext to a third-party crash reporter from the one place that has it.
# Untestable until Redaction.swift was split out of Observability.swift, which
# imports Sentry and so could not be compiled by a slice.
MAIN="$(stage RedactionTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$HELPERS/Redaction.swift" \
  -o "$BINDIR/redactionTests"
"$BINDIR/redactionTests"

echo ""
echo "── Key protection tier (the -25293 fix) ───────"
# Pure mapping checks: capability→tier, tier→LAPolicy, tier→ACL flag, and the
# marker's default. Every Keychain incident this app has had was a mapping that
# drifted, and none of them failed loudly — a `.devicePasscode` key
# authenticated `WithBiometrics` simply never opens.
MAIN="$(stage KeyProtectionTierTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/DeviceAuthCapability.swift" \
  -o "$BINDIR/keyProtectionTierTests"
EXPECTED_SKIPS="$(expected_skips KeyProtectionTierTests)" "$BINDIR/keyProtectionTierTests"

echo ""
echo "── Pure rules (username filter, error text) ───"
# UsernameRule is the ONLY input filter on this client — `sanitized` runs as the
# user types, so it decides whether a paste can reach the field at all. AppError
# is what a person actually reads when something fails. Neither had ever been
# compiled by a test.
MAIN="$(stage PureHelpersTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$HELPERS/UsernameRule.swift" "$MODELS/AppError.swift" \
  -o "$BINDIR/pureHelpersTests"
"$BINDIR/pureHelpersTests"

echo ""
echo "── Link and router (the last uncompiled files) ──"
# MQTTService is an actor over an injected backend and ConversationRouter takes
# every side effect as a closure — both were built to be testable and neither had
# a test. What they decide is not plumbing: which topics a connect asks for, and
# where an inbound frame goes. A topic that routes nowhere is a frame dropped in
# silence, which is the bug ProtocolLog was written for.
# Every non-view file. Built with a glob and an explicit skip list rather than
# `ls | grep`, which shellcheck rejects (SC2010/SC2046) and which breaks on any
# filename with a space in it.
#
# The skip list is the SAME set tests/coverage-report.sh excludes from the
# denominator — SwiftUI layout, design tokens, the app shell, and Observability,
# which imports Sentry and cannot be linked by a slice.
ORCHESTRATOR_SOURCES=()
for f in "$APP"/*.swift "$APP"/Models/*.swift "$APP"/Services/*.swift \
         "$APP"/Helpers/*.swift "$APP"/Core/*.swift; do
  case "${f##*/}" in
    ContentView.swift|DissQusApp.swift|Theme.swift|PlatformColors.swift|\
    StatusPresentation.swift|Observability.swift) continue ;;
  esac
  ORCHESTRATOR_SOURCES+=("$f")
done

MAIN="$(stage OrchestratorTests.swift)"
xcrun swiftc -O $COV_FLAGS -target arm64-apple-macos14 \
  "$MAIN" TestSupport.swift \
  "${ORCHESTRATOR_SOURCES[@]}" \
  -import-objc-header "$APP/Core/HQC-Bridging-Header.h" -I "$APP/Core" \
  -L ".." -lhqc_wrap -Xlinker -rpath -Xlinker "$(cd .. && pwd)" \
  -framework Security \
  -o "$BINDIR/orchestratorTests"
"$BINDIR/orchestratorTests"

echo ""
echo "── Store, migration and reset ─────────────────"
# 1,800 lines that no slice compiled, unlocked by one line of fixture:
# ModelConfiguration(isStoredInMemoryOnly: true). What is asserted is what a user
# would lose if it were wrong — a migration that drops a contact loses their
# history, and a reset that leaves a row behind is an account-deletion claim that
# is not true.
MAIN="$(stage PersistenceTests.swift)"
xcrun swiftc -O $COV_FLAGS -target arm64-apple-macos14 \
  "$MAIN" TestSupport.swift \
  "$APP/Persistence.swift" "$MODELS/Message.swift" "$MODELS/Friend.swift" "$MODELS/Profile.swift" \
  "$MODELS/MessageTypes.swift" "$MODELS/AppError.swift" \
  "$SRC/PeerID.swift" "$SRC/RatchetSession.swift" "$SRC/DoubleRatchet.swift" \
  "$SRC/AESService.swift" "$SRC/BiometricAudit.swift" "$SRC/MessageKeyStore.swift" \
  "$SRC/DeviceAuthCapability.swift" "$SRC/IdentityManager.swift" \
  "$SRC/BiometricCoordinator.swift" "$SRC/HQCService.swift" "$SRC/HQCKem.swift" \
  "$SRC/PrekeyService.swift" "$SRC/APIClient.swift" "$SRC/AuthService.swift" \
  "$SRC/TLSPinning.swift" "$APP/Deployment.swift" "$HELPERS/ProtocolLog.swift" \
  "$SRC/StoreMigration.swift" "$SRC/DataResetService.swift" "$SRC/ProfileManager.swift" \
  -import-objc-header "$APP/Core/HQC-Bridging-Header.h" -I "$APP/Core" \
  -L ".." -lhqc_wrap -Xlinker -rpath -Xlinker "$(cd .. && pwd)" \
  -framework Security \
  -o "$BINDIR/persistenceTests"
"$BINDIR/persistenceTests"

echo ""
echo "── Protocol trace (what Release is allowed to log) ──"
# The one log that survives Release, on a device with no Mac attached. It is only
# allowed to exist because redaction there is by CONSTRUCTION — no Event case can
# carry a payload, a key or a username. Nothing checked that rule, so a case
# added tomorrow could ship free text into the unified log, where `log collect`
# hands it to anyone with the device.
MAIN="$(stage ProtocolLogTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$HELPERS/ProtocolLog.swift" \
  -o "$BINDIR/protocolLogTests"
"$BINDIR/protocolLogTests"

echo ""
echo "── MQTT codec: the refusals ───────────────────"
# MQTTWireTests covers what the codec does with well-formed packets. This covers
# the rest, which is the half that matters for a parser reading a socket. The
# three cases of NextPacket exist because collapsing them is the bug: a hostile
# remaining-length that reads as "nothing yet" leaves the client buffering
# forever.
MAIN="$(stage MQTTCodecEdgeTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift Stubs.swift \
  "$SRC/MQTTWireClient.swift" \
  -o "$BINDIR/mqttCodecEdgeTests"
"$BINDIR/mqttCodecEdgeTests"

echo ""
echo "── Conversation frame (the untrusted seam) ────"
# The one file on this client that reads bytes a stranger sent. e2e/run.sh and
# fuzz/run.sh do exercise it, but neither is instrumented — so it read as zero,
# and nothing asserted its REFUSALS in isolation.
MAIN="$(stage ConversationFrameTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/ConversationFrame.swift" "$SRC/ConversationEnvelopeV3.swift" \
  "$SRC/PeerID.swift" \
  -o "$BINDIR/conversationFrameTests"
"$BINDIR/conversationFrameTests"

echo ""
echo "── REST client (bearer, errors, no enumeration) ──"
# 228 lines never compiled by a test. Not glue: the bearer header, the error
# mapping and the URL each call is pointed at. Driven through a URLProtocol stub
# — the production session is built with the pinning delegate against the real
# origin, which is why none of this was reachable.
MAIN="$(stage APIClientTests.swift)"
# The bridging header is how Swift reaches the C wrappers, and an explicit target
# triple is required for it to be picked up at all in a CLI build — e2e/run.sh
# hit the same trap. AuthService performs the KEM handshake, so the slice needs
# the native library.
xcrun swiftc -O $COV_FLAGS -target arm64-apple-macos13 \
  "$MAIN" TestSupport.swift \
  "$SRC/APIClient.swift" "$SRC/AuthService.swift" "$SRC/TLSPinning.swift" \
  "$SRC/AESService.swift" "$SRC/BiometricAudit.swift" \
  "$SRC/HQCService.swift" "$SRC/PeerID.swift" "../DissQus/Deployment.swift" \
  -import-objc-header "../DissQus/Core/HQC-Bridging-Header.h" \
  -I "../DissQus/Core" \
  -L ".." -lhqc_wrap \
  -Xlinker -rpath -Xlinker "$(cd .. && pwd)" \
  -framework Security \
  -o "$BINDIR/apiClientTests"
"$BINDIR/apiClientTests"

echo ""
echo "── TLS pinning (MAS-3) ────────────────────────"
# The one check between this client and anyone holding a certificate a system
# root will vouch for. What is actually fragile is `spkiSHA256`, which rebuilds
# the DER SubjectPublicKeyInfo from a hand-written table of four ASN.1 headers —
# a wrong entry matches no pin, refuses every connection, and looks exactly like
# an attack in the log.
#
# So the fixtures are REAL certificates and the expected digest is computed by
# openssl, not restated in Swift. Generated per run: Swift has no X.509 writer,
# and a committed certificate expires.
PIN_FIXTURES="$TMP/pins"
mkdir -p "$PIN_FIXTURES"
gen_pin_fixture() {
  local name="$1"; shift
  openssl req -x509 -nodes -days 2 -subj "/CN=$name.pin.test" \
    "$@" -keyout "$PIN_FIXTURES/$name.key" -out "$PIN_FIXTURES/$name.pem" 2>/dev/null
  openssl x509 -in "$PIN_FIXTURES/$name.pem" -outform der -out "$PIN_FIXTURES/$name.der"
  # The SPKI digest, the way every pinning guide tells you to compute it.
  openssl x509 -in "$PIN_FIXTURES/$name.pem" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -hex \
    | sed 's/.*= *//' > "$PIN_FIXTURES/$name.sha256"
}
gen_pin_fixture rsa2048 -newkey rsa:2048
gen_pin_fixture rsa4096 -newkey rsa:4096
gen_pin_fixture ec256   -newkey ec -pkeyopt ec_paramgen_curve:prime256v1
gen_pin_fixture ec384   -newkey ec -pkeyopt ec_paramgen_curve:secp384r1

MAIN="$(stage TLSPinningTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/TLSPinning.swift" "../DissQus/Deployment.swift" \
  -framework Security \
  -o "$BINDIR/tlsPinningTests"
"$BINDIR/tlsPinningTests" "$PIN_FIXTURES"

echo ""
echo "── Shared auth context (one prompt, two stores) ──"
# The LAContext shared between ProfileManager and MessageKeyStore so a tier-1
# profile costs ONE unlock per session rather than one per key store. Three
# pieces of interacting mutable state reached from two call sites; two commits in
# #133 exist because the two auth sheets raced. Nothing covered the sharing
# protocol itself until now.
MAIN="$(stage SharedAuthContextTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift Stubs.swift \
  "$MODELS/Message.swift" "$MODELS/Friend.swift" "$MODELS/Profile.swift" \
  "$SRC/MessageKeyStore.swift" "$SRC/DeviceAuthCapability.swift" \
  "$SRC/AESService.swift" "$SRC/RatchetSession.swift" \
  "$SRC/DoubleRatchet.swift" "$SRC/PeerID.swift" \
  "$SRC/BiometricAudit.swift" "$SRC/BiometricCoordinator.swift" \
  -o "$BINDIR/sharedAuthContextTests"
"$BINDIR/sharedAuthContextTests"

echo ""
echo "── Message at-rest tests ──────────────────────"
MAIN="$(stage MessageAtRestTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift Stubs.swift \
  "$MODELS/Message.swift" "$MODELS/Friend.swift" "$MODELS/Profile.swift" \
  "$SRC/MessageKeyStore.swift" "$SRC/DeviceAuthCapability.swift" \
  "$SRC/AESService.swift" "$SRC/RatchetSession.swift" \
  "$SRC/DoubleRatchet.swift" "$SRC/PeerID.swift" \
  "$SRC/BiometricAudit.swift" "$SRC/BiometricCoordinator.swift" \
  -o "$BINDIR/atRestTests"
EXPECTED_SKIPS="$(expected_skips MessageAtRestTests)" "$BINDIR/atRestTests"

echo ""
echo "✅ All Swift tests passed"
