#!/usr/bin/env bash
#
# Fuzzing driver for the Apple client. Compiles the REAL service sources (no
# copies) together with the harness, exactly as tests/run.sh does — and with the
# same caveat: every slice must list its FULL transitive source set, because
# there is no target here to resolve one.
#
#   ./run.sh seeds                      regenerate the seed corpus
#   ./run.sh mqtt-wire                  fuzz MQTTCodec (native driver)
#   ./run.sh mqtt-wire --iterations 1000000 --seed 7
#   ./run.sh mqtt-wire --asan           add AddressSanitizer (slower)
#   ./run.sh mqtt-wire --libfuzzer      coverage-guided, needs an LLVM runtime
#   ./run.sh envelope-v3-verdict       …and of the v3 one
#   ./run.sh envelope-v3-encode-verdict  …and of the v3 ENCODE one
#   ./run.sh repro findings/current-input.bin
#
set -euo pipefail
cd "$(dirname "$0")"

SRC="../DissQus/Services"
TESTS="../tests"
BUILD="build"
mkdir -p "$BUILD"

# The mqtt-wire slice. TestSupport/Stubs are here for the same reason
# tests/run.sh passes them to its MQTT slice: MQTTWireClient.swift references
# app-level symbols that only those files provide outside an Xcode target.
MQTT_SOURCES=("$TESTS/TestSupport.swift" "$TESTS/Stubs.swift" "$SRC/MQTTWireClient.swift")

# The envelope slice, mirroring the one in tests/run.sh.
ENVELOPE_V3_SOURCES=("$SRC/ConversationEnvelopeV3.swift" "$SRC/PeerID.swift")

# The scrubber. Foundation only — this is exactly why Redaction.swift was split
# out of Observability.swift, which imports Sentry and could not be built here.
SCRUB_SOURCES=("../DissQus/Helpers/Redaction.swift")

# The topic router. Foundation only; PeerID supplies isWellFormed and the hash.
TOPIC_SOURCES=("$SRC/MQTTTopics.swift" "$SRC/PeerID.swift")

# The handshake frame codec. Foundation + CryptoKit only.
HANDSHAKE_SOURCES=("$SRC/Handshake.swift")

# The ratchet state machine. A stub KEM lives in the target, so no native lib.
RATCHET_SOURCES=("$SRC/DoubleRatchet.swift" "$SRC/RatchetSession.swift")

TARGET="${1:-}"; shift || true

# --- flag extraction (the rest is forwarded to the binary) ------------------
ASAN=0; LIBFUZZER=0; FORWARD=()
for arg in "$@"; do
  case "$arg" in
    --asan)      ASAN=1 ;;
    --libfuzzer) LIBFUZZER=1 ;;
    *)           FORWARD+=("$arg") ;;
  esac
done

find_fuzzer_runtime() {
  # Xcode ships ASan/TSan/UBSan but NOT libFuzzer, so this looks for an
  # open-source LLVM (`brew install llvm`) instead.
  local prefix
  prefix="$(brew --prefix llvm 2>/dev/null || true)"
  [ -n "$prefix" ] || return 1
  find "$prefix/lib/clang" -name 'libclang_rt.fuzzer_osx.a' 2>/dev/null | head -1
}

case "$TARGET" in

  seeds)
    echo "── generating seed corpus ─────────────────────"
    cp GenSeeds.swift "$BUILD/main.swift"
    xcrun swiftc -O "$BUILD/main.swift" "${MQTT_SOURCES[@]}" -o "$BUILD/gen-seeds"
    "$BUILD/gen-seeds" corpus/mqtt-wire
    ;;

  topic-seeds)
    echo "── generating topic seed corpus ───────────────"
    cp GenTopicSeeds.swift "$BUILD/main.swift"
    xcrun swiftc -O "$BUILD/main.swift" "${TOPIC_SOURCES[@]}" -o "$BUILD/gen-topic-seeds"
    "$BUILD/gen-topic-seeds" corpus/topic-route
    ;;

  topic-route)
    # `MQTTTopics.route` on attacker-supplied strings. Listed as unbuilt in
    # README.md until now: every inbound publish carries a topic the sender
    # chose, and route decides which conversation the payload belongs to before
    # anything authenticates who sent it.
    [ -n "$(ls -A corpus/topic-route 2>/dev/null)" ] || { echo "no corpus yet — generating"; "$0" topic-seeds; echo; }
    echo "── building topic-route (native driver) ───────"
    SANITIZE=(); [ "$ASAN" = "1" ] && SANITIZE=(-sanitize=address)
    cp TopicRouteMain.swift "$BUILD/main.swift"
    xcrun swiftc -g -O "${SANITIZE[@]}" \
      "$BUILD/main.swift" Engine.swift Mutator.swift TopicRouteTarget.swift \
      "${TOPIC_SOURCES[@]}" \
      -o "$BUILD/fuzz-topic-route"
    mkdir -p findings
    exec "$BUILD/fuzz-topic-route" --corpus corpus/topic-route --findings findings "${FORWARD[@]}"
    ;;

  mqtt-wire)
    [ -n "$(ls -A corpus/mqtt-wire 2>/dev/null)" ] || { echo "no corpus yet — running seeds first"; "$0" seeds; echo; }

    if [ "$LIBFUZZER" = "1" ]; then
      RUNTIME="$(find_fuzzer_runtime || true)"
      if [ -z "$RUNTIME" ]; then
        cat >&2 <<'MSG'
❌ no libFuzzer runtime found.

Apple's toolchain refuses `-sanitize=fuzzer` on arm64-apple-macos and ships no
libclang_rt.fuzzer_osx.a. Two ways to get coverage-guided fuzzing:

  brew install llvm         then re-run with --libfuzzer
  (or) fuzz on Linux in Docker, where `swiftc -sanitize=fuzzer` works natively

Until then the native driver runs with no extra installs — it is coverage-blind,
which is a real limitation, not a formality. See README.md.
MSG
        exit 1
      fi
      echo "── building (libFuzzer: $RUNTIME) ─────────────"
      # Swift emits libFuzzer-compatible coverage via -sanitize-coverage, then
      # the runtime supplying main() is linked in by hand. `-parse-as-library`
      # keeps Swift from generating a main() of its own.
      xcrun swiftc -g -O -parse-as-library \
        -sanitize=address \
        -sanitize-coverage=edge,inline-8bit-counters,trace-cmp \
        MQTTWireTarget.swift "${MQTT_SOURCES[@]}" \
        -Xlinker "$RUNTIME" \
        -o "$BUILD/fuzz-mqtt-wire"
      mkdir -p findings
      exec "$BUILD/fuzz-mqtt-wire" corpus/mqtt-wire \
        -artifact_prefix=findings/ -rss_limit_mb=2048 -timeout=25 "${FORWARD[@]}"
    fi

    echo "── building (native driver$([ "$ASAN" = 1 ] && echo ', asan')) ──"
    SANITIZE=(); [ "$ASAN" = "1" ] && SANITIZE=(-sanitize=address)
    cp FuzzMain.swift "$BUILD/main.swift"
    xcrun swiftc -g -O "${SANITIZE[@]}" \
      "$BUILD/main.swift" Engine.swift Mutator.swift MQTTWireTarget.swift \
      "${MQTT_SOURCES[@]}" \
      -o "$BUILD/fuzz-mqtt-wire"
    echo
    exec "$BUILD/fuzz-mqtt-wire" --corpus corpus/mqtt-wire --findings findings "${FORWARD[@]}"
    ;;

  envelope-v3-verdict)
    # Builds the Swift half of the differential harness. The TypeScript driver
    # (services/server/test/fuzz/envelope-v3-differential.ts) runs the binary
    # this produces; it does not build it, so that a Swift compile error
    # surfaces here rather than as a mystery inside the driver.
    #
    # There was a v2 sibling — `envelope-verdict`, over ConversationEnvelopeV2 —
    # and it went with the format it compared.
    echo "── building envelope-v3-verdict ───────────────"
    cp EnvelopeV3Verdict.swift "$BUILD/main.swift"
    xcrun swiftc -O "$BUILD/main.swift" "${ENVELOPE_V3_SOURCES[@]}" -o "$BUILD/envelope-v3-verdict"
    echo "built $BUILD/envelope-v3-verdict"
    ;;

  envelope-v3-encode-verdict)
    # The ENCODE half. The decode harness proved the two parsers agree on the
    # same bytes and said nothing about the encoders — which is where they
    # actually disagreed, on every malformed input.
    echo "── building envelope-v3-encode-verdict ────────"
    cp EnvelopeV3EncodeVerdict.swift "$BUILD/main.swift"
    xcrun swiftc -O "$BUILD/main.swift" "${ENVELOPE_V3_SOURCES[@]}" -o "$BUILD/envelope-v3-encode-verdict"
    echo "built $BUILD/envelope-v3-encode-verdict"
    ;;

  scrub-verdict)
    # The Swift half of the scrubber differential. Driven by
    # services/server/test/fuzz/scrub-differential.ts, which compares this
    # against lib/scrub.ts on identical inputs.
    #
    # The pair is maintained by hand and each file asks the next person to keep
    # them in step; this is the first thing that checks whether anyone did. A
    # divergence here leaks a secret from whichever side redacts less.
    echo "── building scrub-verdict ─────────────────────"
    cp ScrubVerdict.swift "$BUILD/main.swift"
    xcrun swiftc -O "$BUILD/main.swift" "${SCRUB_SOURCES[@]}" -o "$BUILD/scrub-verdict"
    echo "built $BUILD/scrub-verdict"
    ;;

  handshake-verdict)
    # The Swift half of the handshake differential. Driven by
    # services/server/test/fuzz/handshake-differential.ts.
    #
    # h/{friendshipHash} carries the exchange that closes the impersonation gap
    # an init leaves open — an init is built from public values and lands on a
    # topic every friend may publish to, so the challenge and proof are what
    # establish who is actually there. Both ends parse the frame with hand-written
    # offset arithmetic, and nothing has compared them on anything but the five
    # pinned vectors.
    echo "── building handshake-verdict ─────────────────"
    cp HandshakeVerdict.swift "$BUILD/main.swift"
    xcrun swiftc -O "$BUILD/main.swift" "${HANDSHAKE_SOURCES[@]}" -o "$BUILD/handshake-verdict"
    echo "built $BUILD/handshake-verdict"
    ;;

  ratchet-state)
    # `RatchetSession.open` against attacker-chosen n and pn. The last unbuilt
    # target on this README's ladder: "what does a frame claiming n = 1_999_999
    # cost?" Those fields are read to CHOOSE the message key, so they cannot have
    # been authenticated by the payload that key opens — everything the receiver
    # does with them happens before the tag is checked, on the MainActor.
    #
    # No corpus of its own: the interesting inputs are STRUCTURAL (Int.min,
    # maxSkipped ± 1, 2^31), so the target draws them from a table rather than
    # mutating bytes toward them. The engine still supplies the driving entropy.
    [ -n "$(ls -A corpus/ratchet-state 2>/dev/null)" ] || {
      mkdir -p corpus/ratchet-state
      for i in 1 2 3 4 5 6 7 8; do
        head -c 64 /dev/urandom > "corpus/ratchet-state/seed-$i.bin"
      done
      echo "seeded corpus/ratchet-state with 8 random driver inputs"
    }
    echo "── building ratchet-state (native driver) ─────"
    SANITIZE=(); [ "$ASAN" = "1" ] && SANITIZE=(-sanitize=address)
    cp RatchetStateMain.swift "$BUILD/main.swift"
    xcrun swiftc -g -O "${SANITIZE[@]}" \
      "$BUILD/main.swift" Engine.swift Mutator.swift RatchetStateTarget.swift \
      "${RATCHET_SOURCES[@]}" \
      -o "$BUILD/fuzz-ratchet-state"
    mkdir -p findings
    exec "$BUILD/fuzz-ratchet-state" --corpus corpus/ratchet-state --findings findings "${FORWARD[@]}"
    ;;

  repro)
    # Replays ONE input. This is what a finding becomes: not "the fuzzer crashed"
    # but a file you can hand to a debugger and, once fixed, paste into
    # tests/MQTTWireTests.swift as a permanent regression case.
    INPUT="${FORWARD[0]:-}"
    [ -f "$INPUT" ] || { echo "usage: ./run.sh repro <file>" >&2; exit 2; }
    cat > "$BUILD/main.swift" <<'REPRO'
import Foundation
let path = CommandLine.arguments[1]
let data = try! Data(contentsOf: URL(fileURLWithPath: path))
print("replaying \(data.count) bytes from \(path)")
fuzzMQTTWire(data)
print("returned cleanly — this input no longer reproduces")
REPRO
    xcrun swiftc -g -O "$BUILD/main.swift" MQTTWireTarget.swift "${MQTT_SOURCES[@]}" \
      -o "$BUILD/repro"
    exec "$BUILD/repro" "$INPUT"
    ;;

  *)
    sed -n '3,14p' "$0"
    exit 2
    ;;
esac
