#!/usr/bin/env bash
#
# The honest Swift coverage number.
#
# Counterpart to services/server/scripts/coverage-report.ts, and it exists for
# the same reason: llvm-cov reports on the files that were COMPILED INTO a test
# binary, and this project compiles explicit source lists (see run.sh). A file no
# slice lists does not appear as 0% — it does not appear at all. Two thirds of the
# app's Swift files are in that position, so a report over llvm-cov's output alone
# would describe a third of the app and call it the whole thing.
#
# SCOPE: the tests/run.sh slices only. e2e/run.sh and fuzz/run.sh compile some
# further files (ConversationFrame, HQCService, HQCKem) without instrumentation,
# so those read as unreached here. Instrumenting them is the obvious next
# increment; until then this number is a floor, not an estimate.
#
# So the denominator comes from the filesystem instead:
#
#   REACHED  llvm-cov's line coverage over files a slice actually compiles.
#   HONEST   every app source file weighted by line count, unreached at zero.
#
# Excluded from the denominator, deliberately: Views/ and Helpers/Theme.swift.
# Line coverage over a SwiftUI `body` measures layout, not behaviour — those are
# covered by the XCUITest suite instead. Everything else is in scope.
#
# Usage:  COVERAGE=1 bash tests/run.sh && bash tests/coverage-report.sh
set -euo pipefail
cd "$(dirname "$0")"

COV_DIR="${COV_DIR:-$PWD/.coverage}"
APP="../DissQus"

[ -d "$COV_DIR" ] || { echo "❌ no $COV_DIR — run: COVERAGE=1 bash tests/run.sh" >&2; exit 2; }

shopt -s nullglob
raw=("$COV_DIR"/*.profraw)
bins=("$COV_DIR"/bin/*)
shopt -u nullglob
[ ${#raw[@]} -gt 0 ]  || { echo "❌ no .profraw in $COV_DIR" >&2; exit 2; }
[ ${#bins[@]} -gt 0 ] || { echo "❌ no binaries in $COV_DIR/bin" >&2; exit 2; }

xcrun llvm-profdata merge -sparse "${raw[@]}" -o "$COV_DIR/merged.profdata"

# ONE EXPORT PER BINARY, not one export over all of them.
#
# `llvm-cov export -object a -object b` produces a single merged view, and for a
# file compiled into both it does not union what each reached — it picks one
# mapping. That silently masked real coverage the moment a broad slice appeared:
# the orchestrator slice compiles every file and exercises almost none, and after
# it landed Persistence read 0/163 and TLSPinning fell from 82% to 37%, both of
# which have focused slices that cover them.
#
# So each binary is exported separately and the reader below takes the BEST
# result per file. A file covered 90% by its own slice and 0% by a slice that
# merely links it is 90% covered.
: > "$COV_DIR/coverage.jsonl"
for b in "${bins[@]}"; do
  # `llvm-cov export` emits no trailing newline, so without the echo every
  # document lands on one line and the reader chokes on "Extra data".
  xcrun llvm-cov export -instr-profile "$COV_DIR/merged.profdata" -object "$b" \
    2>/dev/null >> "$COV_DIR/coverage.jsonl"
  echo >> "$COV_DIR/coverage.jsonl"
done

APP_DIR="$(cd "$APP" && pwd)" COV_JSON="$COV_DIR/coverage.jsonl" python3 - <<'PY'
import json, os, collections

app  = os.environ["APP_DIR"]
# One JSON document per line, one per test binary.
docs = [json.loads(l) for l in open(os.environ["COV_JSON"]) if l.strip()]

# --- what llvm-cov reached ---------------------------------------------------
# A file can appear once per -object; keep the best result for each.
reached = {}
for doc in docs:
  for export in doc.get("data", []):
    for f in export.get("files", []):
        path = os.path.realpath(f["filename"])
        if not path.startswith(os.path.realpath(app)):
            continue          # TestSupport/Stubs/main.swift are harness, not app
        s = f["summary"]["lines"]
        prev = reached.get(path)
        # Best result wins: a file covered by its own slice and merely LINKED by
        # a broader one is as covered as its own slice made it.
        if prev is None or s["covered"] > prev["covered"]:
            reached[path] = {"count": s["count"], "covered": s["covered"]}

# --- the denominator, from the filesystem ------------------------------------
# Each entry is a REASON, not a convenience. An auditor should be able to read
# this list and disagree with it — which is why the report prints it.
EXCLUSIONS = [
    # SwiftUI layout. Covered by the XCUITest bundle, not by a swiftc slice: a
    # `some View` body has no return value a unit test can assert on. Checked
    # rather than assumed — ContentView's only non-`body` members are private
    # `-> some View` helpers, so there is no state-mapping logic left in it to
    # lift out.
    (lambda r: r.startswith("Views/"),            "SwiftUI layout"),
    (lambda r: r == "ContentView.swift",          "SwiftUI layout (7 View structs, no non-view logic)"),
    (lambda r: r == "Helpers/StatusPresentation.swift", "SwiftUI layout (5 View structs)"),
    (lambda r: r == "Helpers/Theme.swift",        "design tokens"),
    (lambda r: r == "Helpers/PlatformColors.swift", "design tokens, per platform"),
    (lambda r: r == "DissQusApp.swift",           "@main app shell — the scene graph, not logic"),
    # Observability imports Sentry, which a swiftc slice cannot link. That is the
    # documented reason Redaction.swift was split out of it: the pure half IS
    # Redaction.swift and is covered. What remains here is the Sentry adapter.
    (lambda r: r == "Helpers/Observability.swift", "imports Sentry; its pure half is Redaction.swift, which is covered"),
]

def exclusion_reason(rel):
    for match, why in EXCLUSIONS:
        if match(rel):
            return why
    return None

def excluded(rel):
    return exclusion_reason(rel) is not None

files = []
skipped = []
for root, dirs, names in os.walk(app):
    dirs[:] = [d for d in dirs if d not in (".build", "DerivedData")]
    for n in sorted(names):
        if not n.endswith(".swift"):
            continue
        full = os.path.realpath(os.path.join(root, n))
        rel  = os.path.relpath(full, os.path.realpath(app))
        loc = sum(1 for _ in open(full, encoding="utf-8", errors="replace"))
        why = exclusion_reason(rel)
        if why:
            skipped.append({"rel": rel, "loc": loc, "why": why})
            continue
        c   = reached.get(full)
        pct = (100.0 * c["covered"] / c["count"]) if c and c["count"] else 0.0
        files.append({"rel": rel, "loc": loc, "pct": pct, "reached": c is not None,
                      "count": c["count"] if c else 0,
                      "covered": c["covered"] if c else 0})

total_loc = sum(f["loc"] for f in files)
honest    = 100.0 * sum(f["loc"] * f["pct"] / 100 for f in files) / total_loc
hit       = sum(f["covered"] for f in files if f["reached"])
inst      = sum(f["count"]   for f in files if f["reached"])
reached_pct = (100.0 * hit / inst) if inst else 0.0
unreached = sorted((f for f in files if not f["reached"]), key=lambda f: -f["loc"])

print()
print("── Swift coverage, over every app source file ──")
print()
print(f"  files      {len(files)} source · {len(files)-len(unreached)} reached by a slice · {len(unreached)} never compiled")
print(f"  REACHED    {reached_pct:6.1f}%  line coverage within the files a slice compiles")
print(f"  HONEST     {honest:6.1f}%  LOC-weighted over all {total_loc} lines — unreached files count as zero")

if unreached:
    lost = sum(f["loc"] for f in unreached)
    print()
    print(f"  Never compiled into a unit-test slice — {lost} lines ({100.0*lost/total_loc:.1f}% of the source):")
    print("  (e2e/run.sh and fuzz/run.sh compile a few of these — ConversationFrame,")
    print("   HQCService, HQCKem — but neither is instrumented yet, so they read as zero here.)")
    for f in unreached:
        print(f"    {f['loc']:6d}  {f['rel']}")

weak = sorted((f for f in files if f["reached"] and f["pct"] < 90), key=lambda f: f["pct"])
if weak:
    print()
    print("  Reached but under 90% line:")
    for f in weak:
        print(f"    {f['pct']:6.1f}%  {f['rel']:<44} {f['covered']}/{f['count']} instrumented lines")

# Printed so the denominator can be argued with. A coverage number is only worth
# what its denominator is, and an exclusion nobody can see is where one hides.
if skipped:
    lost = sum(f["loc"] for f in skipped)
    print()
    print(f"  Excluded from the denominator — {lost} lines, each for a stated reason:")
    for f in sorted(skipped, key=lambda x: -x["loc"]):
        print(f"    {f['loc']:6}  {f['rel']:<44} {f['why']}")
print()
PY
