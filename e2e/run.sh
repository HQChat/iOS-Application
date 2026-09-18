#!/usr/bin/env bash
#
# run.sh — the Swift end-to-end harness.
#
#   bash apps/apple/e2e/run.sh
#
# Compiles the REAL implementation — the ratchet, the frame codec, the AEAD, the
# identity commitment, the topic vocabulary and the initiator-authentication
# handshake — and links the REAL HQC library, so the
# KEM under test is the shipping one rather than a stub.
#
# What it is not: the app. `ConversationRouter` is @MainActor over SwiftData, so
# the harness mirrors its orchestration rather than importing it (see Party.swift).
# Everything below that line is the shipping code.
set -euo pipefail
cd "$(dirname "$0")"

APPLE="$(cd .. && pwd)"
SRC="$APPLE/DissQus/Services"
CORE="$APPLE/DissQus/Core"
OUT="${E2E_OUT:-${TMPDIR:-/tmp}}/hqchat-e2e-out"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

# The bridging header is how Swift reaches the C wrappers, and an explicit
# target triple is required for it to be picked up at all in a CLI build — the
# macOS target hits the same trap.
xcrun swiftc -O -target arm64-apple-macos13 \
  FileBus.swift Party.swift main.swift \
  "$SRC/DoubleRatchet.swift" "$SRC/RatchetSession.swift" \
  "$SRC/ConversationEnvelopeV3.swift" \
  "$SRC/ConversationFrame.swift" "$SRC/Handshake.swift" \
  "$SRC/PeerID.swift" "$SRC/MQTTTopics.swift" \
  "$SRC/AESService.swift" "$SRC/BiometricAudit.swift" \
  "$SRC/HQCService.swift" "$SRC/HQCKem.swift" \
  -import-objc-header "$CORE/HQC-Bridging-Header.h" \
  -I "$CORE" \
  -L "$APPLE" -lhqc_wrap \
  -Xlinker -rpath -Xlinker "$APPLE" \
  -o "$BUILD/e2e"

"$BUILD/e2e" "$@" "$OUT"
