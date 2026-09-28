#!/usr/bin/env bash
#
# The Swift MQTT client, live, against the local e2e stack's noise-gw and EMQX.
# Called by services/server/test/e2e/run-local.sh with the stack's env set.
set -euo pipefail
cd "$(dirname "$0")"
SRC="../../DissQus/Services"
APP="../../DissQus"
BUILD="$(mktemp -d)"
CFG="$(cd ../../../../services/server && npx tsx test/e2e/provision-client.ts)"
# The test stubs' MQTT seam types, WITHOUT their HQCService stand-in: this
# harness links the real HQC library, because it runs the real handshake.
sed '/^enum HQCService {/,/^}/d' ../../tests/Stubs.swift > "$BUILD/MQTTStubs.swift"
xcrun swiftc -O -target arm64-apple-macos13 \
  main.swift "$BUILD/MQTTStubs.swift" ../../tests/TransportStubs.swift \
  "$SRC/MQTTWireClient.swift" "$SRC/MQTTTransport.swift" "$SRC/NoiseHQN.swift" \
  "$SRC/MQTTConnectProof.swift" "$SRC/HQCService.swift" \
  -import-objc-header "$APP/Core/HQC-Bridging-Header.h" -I "$APP/Core" \
  -L ../.. -lhqc_wrap -Xlinker -rpath -Xlinker "$(cd ../.. && pwd)" \
  -o "$BUILD/hqn-live"
"$BUILD/hqn-live" "$CFG"
