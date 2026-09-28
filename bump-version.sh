#!/usr/bin/env bash
#
# Bump the iOS app's version in the project file: MARKETING_VERSION (what
# becomes CFBundleShortVersionString) gets its patch number raised, and
# CURRENT_PROJECT_VERSION (the build number) goes up by one.
#
#   bash apps/apple/bump-version.sh           # 2.1.1 (2) → 2.1.2 (3)
#   bash apps/apple/bump-version.sh --print   # print the current version, change nothing
#
# Only the `DissQus iOS` target is touched, in Debug AND Release — Xcode keeps
# them separately and a bump applied to one is a bump that does not ship. The
# macOS target stays at 1.0 on purpose: it has no App Store record (see
# docs/product/publishing.md, "Version and build number").
#
# .github/workflows/app-version.yml runs this on every push to main.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PBXPROJ="$HERE/DissQus.xcodeproj/project.pbxproj"
IOS_BUNDLE='"martin.rougeron.DissQus-iOS"'

# Values of KEY across the iOS target's build configurations, one per line.
read_setting() {
  awk -v key="$1" -v bundle="$IOS_BUNDLE" '
    /isa = XCBuildConfiguration;/ { inblock = 1; val = ""; ios = 0; next }
    inblock && $1 == key && $2 == "=" { val = $3; sub(/;$/, "", val) }
    inblock && $1 == "PRODUCT_BUNDLE_IDENTIFIER" && $3 == bundle ";" { ios = 1 }
    inblock && /^[[:space:]]*name = / { if (ios) print val; inblock = 0 }
  ' "$PBXPROJ"
}

# The iOS configurations must agree, or there is no single "current version".
single_value() {
  local key="$1" values
  values="$(read_setting "$key" | sort -u)"
  if [ -z "$values" ] || [ "$(printf '%s\n' "$values" | wc -l)" -ne 1 ]; then
    echo "bump-version: $key is not one value across the iOS configurations: ${values:-<none>}" >&2
    exit 1
  fi
  printf '%s\n' "$values"
}

version="$(single_value MARKETING_VERSION)"
build="$(single_value CURRENT_PROJECT_VERSION)"

if [ "${1:-}" = "--print" ]; then
  echo "$version ($build)"
  exit 0
fi

if ! [[ "$version" =~ ^([0-9]+)\.([0-9]+)(\.([0-9]+))?$ ]]; then
  echo "bump-version: MARKETING_VERSION '$version' is not MAJOR.MINOR[.PATCH]" >&2
  exit 1
fi
new_version="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$(( ${BASH_REMATCH[4]:-0} + 1 ))"
if ! [[ "$build" =~ ^[0-9]+$ ]]; then
  echo "bump-version: CURRENT_PROJECT_VERSION '$build' is not an integer" >&2
  exit 1
fi

new_build="$(( build + 1 ))"

# Buffer each build configuration and rewrite it only once we know it is iOS:
# PRODUCT_BUNDLE_IDENTIFIER comes after both settings in the block.
tmp="$(mktemp)"
awk -v bundle="$IOS_BUNDLE" -v nv="$new_version" -v nb="$new_build" '
  function flush(   i) {
    for (i = 1; i <= n; i++) {
      if (ios && buf[i] ~ /^[[:space:]]*MARKETING_VERSION = /)       sub(/= .*;$/, "= " nv ";", buf[i])
      if (ios && buf[i] ~ /^[[:space:]]*CURRENT_PROJECT_VERSION = /) sub(/= .*;$/, "= " nb ";", buf[i])
      print buf[i]
    }
    n = 0; ios = 0; inblock = 0
  }
  /isa = XCBuildConfiguration;/ { inblock = 1 }
  inblock {
    buf[++n] = $0
    if ($1 == "PRODUCT_BUNDLE_IDENTIFIER" && $3 == bundle ";") ios = 1
    if ($0 ~ /^[[:space:]]*name = /) flush()
    next
  }
  { print }
  END { if (n) flush() }
' "$PBXPROJ" > "$tmp"
cat "$tmp" > "$PBXPROJ"
rm -f "$tmp"

# Re-read what was written rather than trusting the edit.
[ "$(single_value MARKETING_VERSION)" = "$new_version" ] || { echo "bump-version: MARKETING_VERSION did not update" >&2; exit 1; }
[ "$(single_value CURRENT_PROJECT_VERSION)" = "$new_build" ] || { echo "bump-version: CURRENT_PROJECT_VERSION did not update" >&2; exit 1; }

echo "$version ($build) → $new_version ($new_build)"
