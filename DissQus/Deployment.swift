import Foundation

/// Everything that ties this build to ONE deployment, in one file.
///
/// The values below used to be string literals scattered through `ServerConfig`
/// and two views, which is how they drifted apart. A fork
/// changes this file and nothing else; a per-build override is still possible
/// through the Info.plist keys named beside each value.
///
/// Nothing secret belongs here — it ships inside the app bundle and anyone can
/// read it. Secrets live in the Keychain or on the server.
enum Deployment {

    /// The default home server. Overridable per build with Info.plist `ServerHost`,
    /// and per profile in the app (a profile is an identity + a home server).
    ///
    /// ⚠️ THIS VALUE IS IN THE WILD, and this change is a BREAKING one.
    ///
    /// Every build already on a phone carries the host it was compiled with,
    /// and a device pointed at one that stops answering cannot be told where to
    /// go instead. 2.1.0 shipped naming hqchat.martinrougeron.me; until a device
    /// installs 2.1.1 it will keep asking for that host, and when the old record
    /// is retired those installs stop working until they update.
    ///
    /// What makes the update sufficient — no data migration needed — is that
    /// `Profile.serverURL` is nil unless somebody typed a server by hand
    /// (ProfileManager.createProfile), and `ServerConfig.host` falls back to
    /// this constant when it is. Ordinary profiles follow the build. A profile
    /// that names a host deliberately keeps it, which is correct: that is a
    /// self-hoster's choice, not a stale default.
    static let serverHost = "api.hqchat.app"

    /// Where the published legal pages live.
    ///
    /// Derived from `serverHost` again. It was briefly a constant of its own,
    /// for the window in which the site had moved to hqchat.app and the API had
    /// not; there is one host now, so a second constant could only drift.
    ///
    /// ⚠️ Each path below must appear in `worker_paths`
    /// (`infra/cloudflare/variables.tf`), which takes EXACT paths and rejects
    /// globs. A path missing there does not 404 at the edge — it falls through to
    /// the origin, which answers a REST 404, so the failure looks like a broken
    /// link rather than a missing route. The EULA URL in particular is one App
    /// Store Connect fetches, so it is checked by a site test that reads the
    /// Terraform file rather than by anybody noticing.
    ///
    /// A fork changes `serverHost` and this follows it.
    static var siteURL: URL { URL(string: "https://\(serverHost)")! }
    static var eulaURL: URL { siteURL.appendingPathComponent("eula") }
    static var privacyURL: URL { siteURL.appendingPathComponent("privacy") }
    static var termsURL: URL { siteURL.appendingPathComponent("terms") }
    static var supportURL: URL { siteURL.appendingPathComponent("support") }

    /// SHA-256 of the server's SubjectPublicKeyInfo, base64 — the TLS pins.
    ///
    /// EMPTY means system trust only: the chain must still be valid, but any CA
    /// the device trusts is accepted. That is the state MAS-3 describes, and it
    /// is deliberate rather than forgotten, because a wrong pin does not degrade
    /// the app — it BRICKS it, from the client side, where no server-side change
    /// can rescue it.
    ///
    /// Two things to get right before filling this in
    /// (`infra/deploy/scripts/compute-spki-pins.sh` prints candidates):
    ///
    /// 1. **Pin the CA or intermediate, not the leaf.** Cloudflare terminates TLS
    ///    and rotates leaf certificates on its own schedule; a leaf pin will stop
    ///    working without warning and without a deploy.
    /// 2. **Ship at least two pins** — the one in use and a backup from a
    ///    different issuer — or a single revocation strands every installed copy.
    ///
    /// Overridable per build with the Info.plist array `ServerPinnedSPKIHashes`.
    static let pinnedSPKIHashes: [String] = []

    /// Sentry DSN. Deliberately EMPTY in the repo: crash reporting is opt-in per
    /// build (Info.plist `SENTRY_DSN`), so a fork or a local build never posts to
    /// someone else's project. Empty = Sentry disabled, which the app logs.
    static let sentryDSN = ""

    // `wireVersion` stood here, with an Info.plist override (`WireVersion`). It
    // chose which of two wire formats this build EMITTED while acceptance stayed
    // dual, which is what made the v2 → v3 rollout separable into two releases:
    // every build learned to READ v3 first, and only then did anyone start
    // writing it. Both halves are done, so the setting is a choice between one
    // option and nothing. Its server twin, `WIRE_V3_EMIT`, went the same way.
    //
    // Worth keeping in mind if a v4 is ever wanted: this is the shape of the
    // knob, and the sequence it made possible is the reason the removal could be
    // done at all.
}
