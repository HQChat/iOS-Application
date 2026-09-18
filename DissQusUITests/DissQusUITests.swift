//
//  DissQusUITests.swift
//  DissQusUITests
//
//  End-to-end UI smoke tests. They launch the app in DEMO_MODE (env var), which
//  seeds an in-memory store and presents the authenticated UI without a server —
//  so these exercise the real SwiftUI flows (tabs, conversation, settings) with
//  no network/Stripe/Keychain dependency.
//

import XCTest

final class DissQusUITests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    /// Two tests below need a key the app cannot create in an UNSIGNED build.
    /// They are skipped there rather than failed.
    ///
    /// This is MAS-9 in docs/audits/masvs.md — at-rest sealing "cannot be
    /// exercised off real hardware… that coverage now needs a signed device
    /// build" — and it was costing more than the coverage it was protecting.
    /// `verify.sh` is the ONLY gate on the Apple apps, and these two failures
    /// made it exit 65 on every Mac without a device build. A gate that is
    /// always red cannot tell anyone that something new is broken, which is the
    /// entire job of a gate; two honest skips are worth more than two failures
    /// nobody reads.
    ///
    /// The route to zero is a signed run on real hardware, not a change to the
    /// test — the same route MessageAtRestTests and KeyProtectionTierTests take.
    /// Their budget lives in apps/apple/tests/expected-skips.txt, which records
    /// these two beside them.
    /// Set by verify.sh, which is the only thing that runs this bundle and which
    /// knows it passes CODE_SIGNING_ALLOWED=NO. xcodebuild strips the
    /// `TEST_RUNNER_` prefix on its way into this process.
    ///
    /// DECLARED, not detected, and that is the correction. The first version of
    /// this guard asked `SecureEnclave.isAvailable` and skipped nothing, because
    /// that answers a question nobody was asking:
    ///
    ///   · A modern Simulator reports the Enclave as AVAILABLE. The guard was
    ///     written expecting `false` there and got `true`.
    ///   · The Enclave was never the blocker anyway. The failure is `-34018`,
    ///     errSecMissingEntitlement — an unsigned binary has no keychain access
    ///     group, so the data-protection keychain that holds an Enclave key is
    ///     closed to it. The app says so itself: "Signing config, not code".
    ///     That is KeyProtectionTierTests' reason, not MessageAtRestTests'.
    ///   · And a probe in THIS process would be answering for the wrong one:
    ///     XCUITest runs separately from the app under test, so what the runner
    ///     can do says nothing about what the app can do.
    ///
    /// A build flag is the one fact that is actually known here, so it is the
    /// one the skip turns on. A hand-rolled `xcodebuild test-without-building`
    /// without this variable will still fail, which is correct: the tests really
    /// do fail in that build, and only verify.sh is in a position to say why.
    private static let unsignedBuild =
        ProcessInfo.processInfo.environment["HQCAT_UNSIGNED"] == "1"

    private func requireSignedBuild() throws {
        if !Self.unsignedBuild { return }
        throw XCTSkip(
            "unsigned build (MAS-9): no keychain access group, so the app cannot "
            + "create the Enclave-backed key this test depends on — SecKeyCreateRandomKey "
            + "fails with -34018 errSecMissingEntitlement. Needs a signed device build."
        )
    }

    /// - Parameter tab: opens straight onto a tab, skipping a tap when the test
    ///   isn't about navigation itself.
    private func launchDemoApp(tab: String? = nil) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment["DEMO_MODE"] = "1"
        if let tab { app.launchEnvironment["DEMO_TAB"] = tab }
        app.launch()
        return app
    }

    // MARK: - Chats

    /// The app launches straight into the authenticated UI and shows the seeded
    /// contacts (no profile selection / biometric / server in demo mode).
    func testLaunchesIntoChatList() {
        let app = launchDemoApp()
        // sarah_k is a seeded contact — its presence proves the app launched
        // straight into the authenticated Chats tab.
        XCTAssertTrue(app.staticTexts["sarah_k"].waitForExistence(timeout: 20),
                      "Demo chat list should show the seeded contacts")
    }

    /// Opening a conversation shows the seeded message history.
    ///
    /// Enclave-bound even in demo mode: a seeded message is sealed at rest by
    /// `Message.content`'s setter before it can be read back, and without an
    /// Enclave key that seal fails and nothing is persisted to show.
    func testOpenConversationShowsSeededMessages() throws {
        try requireSignedBuild()
        let app = launchDemoApp()
        let sarah = app.staticTexts["sarah_k"]
        XCTAssertTrue(sarah.waitForExistence(timeout: 20))
        sarah.tap()
        XCTAssertTrue(app.staticTexts["Standing by 👍"].waitForExistence(timeout: 10),
                      "The seeded conversation with Sarah should be visible")
    }

    /// The message composer exists in a conversation (input affordance present).
    func testComposerIsPresentInConversation() {
        let app = launchDemoApp()
        let sarah = app.staticTexts["sarah_k"]
        XCTAssertTrue(sarah.waitForExistence(timeout: 20))
        sarah.tap()
        // The placeholder from ChatView's composer.
        let composer = app.textViews["type a message…"].firstMatch
        let field = app.textFields["type a message…"].firstMatch
        XCTAssertTrue(composer.waitForExistence(timeout: 10) || field.waitForExistence(timeout: 1),
                      "The conversation should show the message composer")
    }

    // MARK: - Tab bar

    /// The bottom tab bar replaced the old "…" toolbar menu; all three
    /// destinations must be reachable in one tap.
    func testTabBarExposesAllThreeDestinations() {
        let app = launchDemoApp()
        XCTAssertTrue(app.tabBars.buttons["chats"].waitForExistence(timeout: 20))
        XCTAssertTrue(app.tabBars.buttons["contacts"].exists)
        XCTAssertTrue(app.tabBars.buttons["settings"].exists)
    }

    /// Contacts is one tap away and separates pending invites from established
    /// contacts.
    func testContactsTabSeparatesInvitesFromContacts() {
        let app = launchDemoApp()
        XCTAssertTrue(app.tabBars.buttons["contacts"].waitForExistence(timeout: 20))
        app.tabBars.buttons["contacts"].tap()

        // The screen names itself in the prompt header, not a system nav title.
        XCTAssertTrue(app.staticTexts["contacts"].waitForExistence(timeout: 10))
        // The seeded pending invite gets its own section with an accept action.
        XCTAssertTrue(app.buttons["accept"].waitForExistence(timeout: 10),
                      "A received invite should offer an inline accept")
    }

    /// Adding a contact is a button on the Contacts screen — it used to be a
    /// glyph in the toolbar, which is why nobody found it.
    func testAddContactScreenIsReachable() {
        let app = launchDemoApp(tab: "contacts")
        let add = app.buttons["add contact"]
        XCTAssertTrue(add.waitForExistence(timeout: 20))
        add.tap()
        // Pushed screens wear the app's own prompt header, not a system nav bar,
        // so the whole stack speaks one design language.
        XCTAssertTrue(app.staticTexts["contacts/add"].waitForExistence(timeout: 10))
    }

    // MARK: - Profile creation (real store, no DEMO_MODE)

    /// Creating a profile must land in the app, not on the "no key for this
    /// profile" screen.
    ///
    /// This covers the regression the startup key check caused twice: a probe
    /// ran against a profile whose key had just been stored, decided it was
    /// missing, and sent a working profile to an error screen. There is no such
    /// gate any more. Runs against the real store and the real Keychain path on
    /// purpose; DEMO_MODE would skip all of it.
    func testCreatingProfileEntersTheApp() throws {
        // Genuine HQC keygen and a real Keychain write, on purpose — DEMO_MODE
        // would skip the very thing this covers. Which also means no Enclave, no
        // test.
        try requireSignedBuild()
        let app = XCUIApplication()
        app.launchEnvironment["UITEST_FRESH"] = "1"
        app.launch()

        let newProfile = app.buttons["new profile"].firstMatch
        XCTAssertTrue(newProfile.waitForExistence(timeout: 30),
                      "Onboarding should offer profile creation")
        newProfile.tap()

        // One field: the handle. A profile no longer carries a separate local
        // name, so there is nothing else to fill in.
        let handleField = app.textFields["handle"].firstMatch
        XCTAssertTrue(handleField.waitForExistence(timeout: 10))
        handleField.tap()
        handleField.typeText("uitest\(Int.random(in: 1000...9999))")

        // THREE answers are required, not one. The handle alone used to be
        // enough; the protection tier joined it (nothing preselects it), and the
        // agreement joins it here — App Store Guideline 1.2 wants it obtained
        // before the app is used, and this screen is the last moment before that.
        //
        // The DISABLED assertion is the one that matters. A test that only taps
        // through the gate passes just as well with the gate deleted.
        let create = app.buttons["create"].firstMatch
        XCTAssertTrue(create.waitForExistence(timeout: 10))
        XCTAssertFalse(create.isEnabled,
                       "create must not enable on the handle alone — protection and the agreement are required")

        // Whichever tier this device offers. A device with no biometry shows one
        // non-selectable row, so both spellings are tried rather than assumed.
        for tier in ["Secure", "Quick unlock"] {
            let option = app.buttons.containing(.staticText, identifier: tier).firstMatch
            if option.exists { option.tap(); break }
        }

        let agree = app.buttons["i agree to the terms"].firstMatch
        XCTAssertTrue(agree.waitForExistence(timeout: 10),
                      "the create-profile screen must ask for agreement to the terms")
        agree.tap()

        XCTAssertTrue(create.isEnabled, "create should enable once all three are answered")
        create.tap()

        // Key generation is genuine HQC keygen, so allow real time for it.
        let landed = app.tabBars.buttons["chats"].waitForExistence(timeout: 90)
        XCTAssertTrue(landed, "Creating a profile should enter the app")

        // Relaunching with that profile already active is the other half of the
        // regression: the startup check runs again, and must not send a working
        // profile to an authentication failure.
        app.terminate()
        // Relaunch onto the profile we just made — the fresh-start flag must not
        // carry over, or the relaunch wipes the very thing under test.
        app.launchEnvironment["UITEST_FRESH"] = "0"
        app.launch()

        let landedAgain = app.tabBars.buttons["chats"].waitForExistence(timeout: 60)
        XCTAssertTrue(landedAgain, "Relaunch should go straight back into the app")
    }

    // MARK: - Settings

    /// Settings is a tab, and the technical detail sits behind Security rather
    /// than on the root screen.
    func testSettingsTabShowsAccountAndSecurity() {
        let app = launchDemoApp(tab: "settings")
        XCTAssertTrue(app.staticTexts["account"].waitForExistence(timeout: 20))
        XCTAssertTrue(app.staticTexts["security"].exists)
        // The Face ID app-lock toggle was removed in v2.
        XCTAssertFalse(app.switches["Require Face ID"].exists)
    }

    // MARK: - Destructive flows (App Store Guideline 5.1.1(v))

    /// "Reset all data" must confirm before doing anything.
    func testResetAllDataAsksForConfirmation() {
        let app = launchDemoApp(tab: "settings")
        XCTAssertTrue(app.staticTexts["account"].waitForExistence(timeout: 20))
        app.staticTexts["account"].tap()

        let reset = app.buttons["reset all data on this device"]
        XCTAssertTrue(reset.waitForExistence(timeout: 10))
        reset.tap()

        XCTAssertTrue(app.buttons["Reset everything"].waitForExistence(timeout: 10),
                      "Resetting must go through an explicit confirmation")
        app.buttons["Cancel"].tap()
        // Cancelling leaves the account screen intact.
        XCTAssertTrue(reset.waitForExistence(timeout: 5))
    }

    /// Account deletion must be reachable and must confirm before doing
    /// anything — this is the App Store requirement.
    func testDeleteAccountAsksForConfirmation() {
        let app = launchDemoApp(tab: "settings")
        XCTAssertTrue(app.staticTexts["account"].waitForExistence(timeout: 20))
        app.staticTexts["account"].tap()

        let delete = app.buttons["delete my account"]
        XCTAssertTrue(delete.waitForExistence(timeout: 10),
                      "Account deletion must be reachable in-app")
        delete.tap()

        XCTAssertTrue(app.buttons["Delete account"].waitForExistence(timeout: 10),
                      "Deleting must go through an explicit confirmation")
        app.buttons["Cancel"].tap()
        XCTAssertTrue(delete.waitForExistence(timeout: 5))
    }
}
