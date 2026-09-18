# Fuzzing the Apple client

The client is where the plaintext is. The server never sees a message, so a
parser bug here is not a dropped frame — it is the attack. This directory fuzzes
the code that reads bytes off the network *before* anything authenticates them.

## The toolchain situation, and why the driver is hand-rolled

The obvious approach does not work on a Mac:

```
$ xcrun swiftc -sanitize=fuzzer …
error: unsupported option '-sanitize=fuzzer' for target 'arm64-apple-macosx'
```

Apple's toolchain ships ASan, TSan and UBSan but **no libFuzzer runtime** — there
is no `libclang_rt.fuzzer_osx.a` under Xcode. Coverage *instrumentation* works
(`-sanitize-coverage=edge,inline-8bit-counters,trace-cmp` compiles), so the only
missing piece is the runtime that supplies `main` and the mutation loop.

So there are two drivers here:

| | how to get it | steers by coverage? |
|---|---|---|
| **native** (default) | nothing to install | **no** |
| **libFuzzer** | `brew install llvm`, then `--libfuzzer` | yes |

The native driver runs today and finds shallow bugs. It is **coverage-blind**:
it cannot tell that an input reached a new branch, so it cannot steer toward one.
It is a random walk around the seed corpus, and its reach is bounded by the
corpus and by `Mutator.swift`. Treat that as a real limitation — the difference
between the two drivers is the whole reason coverage guidance was invented.

A third option, if the Homebrew LLVM link proves fiddly: fuzz on Linux in Docker,
where `swiftc -sanitize=fuzzer` is supported natively. `MQTTCodec` uses only
`Foundation.Data`, so it builds there unchanged.

## Layout

| file | who owns it |
|---|---|
| `Engine.swift` | driver — PRNG, corpus, loop, crash capture. Done. |
| `GenSeeds.swift` | seed corpus, built from the real encoders. Done. |
| `run.sh` | build + run. Done. |
| `Mutator.swift` | **the mutation strategies — yours** |
| `MQTTWireTarget.swift` | **the decoders to call and the oracle — yours** |
| `TopicRouteTarget.swift` | `MQTTTopics.route` and its consistency oracles |
| `GenTopicSeeds.swift` | the topic corpus, built from the real topic builders |
| `ScrubVerdict.swift` | the Swift half of the scrubber differential |
| `HandshakeVerdict.swift` | the Swift half of the handshake differential |

`corpus/` is committed on purpose: it is the fuzzer's accumulated knowledge.
`findings/` and `build/` are not.

## Running it

```bash
./run.sh seeds                                  # regenerate the corpus
./run.sh mqtt-wire                              # 200k iterations, seed 1
./run.sh mqtt-wire --iterations 5000000 --seed 7
./run.sh mqtt-wire --asan                       # slower; for the C boundary
./run.sh repro findings/current-input.bin       # replay one input
```

## When it crashes

A Swift trap is a hard process kill — no catch, no `defer`, no chance to write
anything afterwards. So `Engine.swift` persists each input **before** running it.
Whatever is in `findings/current-input.bin` when the process dies is the input
that killed it. (libFuzzer does the same thing under `-artifact_prefix`; here it
is explicit rather than magic.)

The workflow from there:

1. `./run.sh repro findings/current-input.bin` — confirm it reproduces.
2. Copy it aside; `current-input.bin` is overwritten by the next run.
3. Shrink it by hand until every remaining byte is load-bearing. A 4-byte
   reproducer explains itself; a 300 KB one does not.
4. Fix the bug.
5. **Paste the shrunk bytes into `tests/MQTTWireTests.swift` as a permanent
   case, and add the file to `corpus/`.** This is the step that matters: the
   fuzz run is a soak you do occasionally, the regression test runs forever.

## Targets

**`mqtt-wire` (built).** `MQTTCodec` in `Services/MQTTWireClient.swift` — a
hand-rolled MQTT 3.1.1 decoder fed straight from `URLSessionWebSocketTask` by
`ingest(_:)`, with manual index arithmetic throughout (`body[base + 1]`,
`body[cursor + 1]`, `body[(start + 2)...]`). In Swift an out-of-bounds `Data`
subscript **traps**, as does `Int` overflow, so "the process is still alive" is a
genuine oracle here and a crash is a remote DoS.

**`mqtt-wire` resource bounds (built).** Folded into the same target rather than
given one of its own, because it is a property of the same loop: an
`.incomplete` verdict is only legal for a packet that could still fit under
`MQTTCodec.maxPacketBytes`, and no accepted packet may exceed it. Before the
ceiling existed, a five-byte header claiming 256 MB made `ingest` wait and
buffer forever while keepalive reported a healthy link; `decodeLength` now
answers `.malformed` where it used to answer "not yet", and the client fails the
connection.

**`envelope-v3-verdict` (built).** The same idea as the v2 differential, for the
binary framing, with a third oracle: the DECODED FIELDS must agree too. v3 reads
integers out of byte offsets rather than out of a parsed object, so two
implementations can accept the same frame, produce the same AAD, and still
disagree about what `n` is — a shape JSON could not produce. Driven by
`services/server/test/fuzz/envelope-v3-differential.ts`, whose mutations are
aimed at the header rather than spread over the 58 kB of KEM material where
nothing is parsed.

**`envelope-v3-encode-verdict` (built).** The same two implementations from the
other end. Everything else here fuzzes DECODERS; the encoders were the half
nobody had pointed a fuzzer at, and they disagreed on every malformed input —
TypeScript copies into a fixed buffer so a short field pads with zeros and a long
one clips, Swift appends so a wrong length shifts every field after it, and
`writeUInt32BE` throws where `UInt32(truncatingIfNeeded:)` wraps. Structs in,
frames out, two oracles: the same structs are refused, and the accepted ones
produce identical bytes. No mutation corpus — the interesting inputs are
structural, so a generator is enough.

**`topic-route` (built).** `MQTTTopics.route` decides which conversation an
inbound message belongs to, from a string the sender chose, before anything
authenticates who sent it. The oracles are about CONSISTENCY rather than
entitlement — the broker's ACL is what stops a stranger publishing at all, and
`route` deliberately leans on that instead of re-deriving the friendship hash.
What must hold is that the decision is total, deterministic, agrees with
`peer(in:)` about which peer a topic names, and that the app's own builders
round-trip through it.

It found one thing in its first two thousand inputs: Swift's `split(separator:)`
drops empty segments by default, so `u//{id}//presence`, `/u/{id}/presence` and
`u/{id}/presence/` all classified as presence for the same peer. An empty level
is legal and meaningful in MQTT, so those are four different topics. Not
reachable through the broker — the ACL grants exact strings — but a classifier
should not be the part relying on that. Pinned in `tests/MQTTTopicsTests.swift`.

**`scrub-verdict` (built).** The Sentry scrubber, `Redaction.swift` against
`services/server/lib/scrub.ts`. One rule set maintained twice, with each file
asking the next person to keep it in step and nothing checking. Driven by
`services/server/test/fuzz/scrub-differential.ts` in two modes — the textual
redactors and the sensitive-key predicate. It found a ReDoS that hung both
engines for over ten minutes on a 71-character input, and a key-name split that
made the *client* — the side that holds plaintext — redact less than the server.

**`handshake-verdict` (built).** The `h/{friendshipHash}` frame, both directions.
That exchange is what closes the gap an `init` leaves open — an init is built
from public values and lands on a topic every friend may publish to, so the
challenge and proof are what establish who is actually there. Both ends parse it
with hand-written offset arithmetic and the only thing comparing them was five
pinned vectors they agree on by construction. Three modes: `decode`, `encode`
(the half that diverged on every malformed input for the envelope), and `round`,
which checks each side is its own inverse.

Clean so far. Worth saying what that is worth: the driver was validated by
injecting three divergences into the TypeScript half and confirming it reports
each one. The third — an off-by-one in the ct length bound — was NOT caught at
first, because reaching `HS_MAX_CT_BYTES` needs a frame that is actually a
megabyte, and rewriting the length prefix on a 300-byte frame makes both sides
refuse on the total-length check long before the bound is consulted. They agreed
for the wrong reason. `boundaryChallenge` builds the self-consistent frames that
make the check reachable. An unvalidated differential reporting "no divergence"
says nothing.

**`ratchet-state` (built).** `RatchetSession.open` against attacker-chosen `n`
and `pn` — the ladder's own last entry, "what does a frame claiming
`n = 1_999_999` cost?". Those fields are read to CHOOSE the message key, so they
cannot have been authenticated by the payload that key opens: everything the
receiver does with them happens before the tag is checked, on the MainActor.

Two things this target taught, both about instruments rather than about the
ratchet:

- **An elapsed-time oracle cannot catch a hang.** Timing the call and asserting
  it was fast never runs if the call does not return, and removing the pre-walk
  bound makes `open` spend two billion HKDF invocations. The fuzzer just hung.
  There is a watchdog now, armed before the call.
- **A watchdog measures the scheduler too.** At a 5-second limit it fired once
  under full machine load on a case that would not reproduce — the worst real
  `open` measures 23ms. The limit is 30s, which still catches a bug that ran past
  ten minutes.

The target counts its own reach (`accepted`, `replays-refused`, `cache-grew`) and
prints it at exit, because an earlier generator produced almost only fabricated
headers that `open` refuses in its first few lines — the replay oracle never
executed, and an injected defect went undetected while the run stayed green.

**Not yet built:** nothing from the original ladder. The next targets are new
ones — `ConversationRouter`'s pending-frame handling (an init and a message
arrive on different topics, so their order is not guaranteed), and the shared
`LAContext` state machine.
