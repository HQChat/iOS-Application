# End-to-end, in Swift

One command runs a whole interaction through the real implementation:

```bash
bash apps/apple/e2e/run.sh
```

## What it actually exercises

The **real** ratchet, the frame codec, the AEAD, the
identity commitment, the topic vocabulary and the initiator-authentication
handshake — compiled straight from `DissQus/Services`. The KEM is **real HQC**
through the app's own adapter (`HQCKem` → `HQCService` → `libhqc_wrap`), not a
stub, which is what makes this end-to-end rather than a state-machine test.

The script:

1. **Friend request** — each side pins the other's key, and a key that does not
   hash to the id that named it is refused. The `mqtt_acl` grant set is modelled,
   including the handshake topic, which is granted to the two members and nobody
   else.
2. **First contact** — an `init` to the peer's inbox, which is *held rather than
   opened*: it proves nothing about who sent it. The receiver challenges, the
   sender proves possession of its identity key, and only then does the message
   open.
3. **Five messages each way**, delivered on every turn so the ratchet actually
   flips direction rather than running as two one-way streams.
4. **Integrity** — every message arrived in order and byte-identical, multi-byte
   text survived, nothing was delivered twice, a byte-identical replay yielded
   nothing, and the conversation survived it.

## The bus is a directory

Every packet is written to a file and read back before it is parsed, so a round
trip through the filesystem is part of the test rather than something the
harness optimises away.

Packets are stored as **hex**, one line per file. A v3 frame is binary and a v2
frame is UTF-8 JSON, and a harness that guessed wrong about which it held would
corrupt exactly the thing under test — hex has no such failure mode, survives any
editor or diff, and a truncated write is visibly truncated. Each packet's
SHA-256 goes in `manifest.tsv` and is verified on read, so a file that changed
between write and read is caught at the bus rather than surfacing as a
decryption failure three layers up.

The transcript is worth reading. From one run:

```
seq  topic                     from      bytes    sha256
1    u/440ba878…/inbox         88fb5bbd  83260B   892441b4…   ← the init
2    h/9a06604a…                440ba878  14527B   25e0c1f2…   ← the challenge
3    h/9a06604a…                88fb5bbd    134B   982a7683…   ← the proof
4    c/9a06604a…                440ba878  29620B   e077e8a0…   ← first reply, stepping
```

Same script, both versions, for comparison:

| | init | largest msg | smallest msg | 16 packets |
|---|---|---|---|---|
| v2 | 83,282 B | 29,560 B | 264 B | 131,450 B |
| v3 | 57,967 B | 21,841 B | 177 B | 97,170 B |

## What it is not

**It is not the app.** `ConversationRouter` is `@MainActor` over SwiftData, so
importing it would mean a model container, a Keychain, a profile and a biometric
prompt — none of which says anything about the protocol. `Party.swift` therefore
**mirrors** the router's orchestration (hold an init, challenge, prove, open),
and that is a real caveat: a divergence between the two would not be caught here.
It is written to be read side by side with the original.

**It is not a broker.** Ordering, QoS and the ACL are modelled; sockets are not.
`services/server/test/e2e` covers the real EMQX path, and needs Docker to do it.
