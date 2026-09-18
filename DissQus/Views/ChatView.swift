//
//  ChatView.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import SwiftUI
import SwiftData
import CryptoKit

/// What a report is about, snapshotted at the moment the user asks for it.
///
/// A VALUE, carrying its own id, and both halves of that are deliberate.
///
/// The sheet used to be handed a live `Message`. A `Message` is a SwiftData
/// model, so its `Identifiable.id` is a `PersistentIdentifier` — an identifier
/// the store owns and is free to change, and `markRead` writes and saves
/// exactly the newest unread messages the instant this screen appears. Keying a
/// presentation on that means keying it on the one thing in the app most likely
/// to move while the user is reaching for it. A `UUID` we mint cannot move, and
/// a snapshot of the text cannot be re-keyed, deleted, or re-decrypted out from
/// under a half-filled form.
///
/// `excerpt` and `messageId` are optional because a report filed from the header
/// is about the CONVERSATION, not one message. That is not a degraded case the
/// server tolerates — `excerpt`, `frame` and `messageId` are each nullable in
/// 006_reports.sql, and its own comment calls a metadata-only report the first
/// shipped shape of this feature.
struct ReportDraft: Identifiable {
    let id = UUID()
    /// The reporter's copy of one message, or nil to report the conversation.
    let excerpt: String?
    /// The frame's id, when the report is about a specific message.
    let messageId: String?
}

struct ChatView: View {
    let friend: Friend
    let session: ChatSession
    let profileManager: ProfileManager?
    
    @Environment(\.modelContext) private var modelContext
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var appState: AppState
    /// See `MessageKeyGate`: bodies are sealed at rest, and the single unlock
    /// that opens them is asked for when this screen appears, not per row.
    @ObservedObject private var messageKeys = MessageKeyGate.shared
    @Query private var messages: [Message]
    
    @State private var messageText = ""
    @State private var isSending = false
    @State private var appError: AppError?
    @State private var showingProfileSelector = false
    @State private var isSearching = false
    @State private var searchText = ""
    @State private var showingVerification = false
    /// What the user asked to report. Nil means no sheet — the target and the
    /// presentation state are one value, so they cannot disagree.
    @State private var reportDraft: ReportDraft?
    @FocusState private var composerFocused: Bool

    // V0 carries text only. Photos, voice notes and calls come back in a later
    // phase, over MQTT — see deploy/EXTRACTION_PLAN.md.

    /// Messages shown in the list, filtered by the in-chat search query.
    private var displayedMessages: [Message] {
        guard !searchText.isEmpty else { return messages }
        return messages.filter { $0.content.localizedCaseInsensitiveContains(searchText) }
    }

    /// The day label to draw above `message`, or nil when the previous message
    /// was on the same day. Computed against `displayedMessages` so search
    /// results stay correctly grouped.
    private func daySeparator(before message: Message) -> String? {
        let list = displayedMessages
        guard let i = list.firstIndex(where: { $0.id == message.id }) else { return nil }
        if i > 0, Calendar.current.isDate(list[i - 1].timestamp,
                                          inSameDayAs: message.timestamp) { return nil }
        return Self.dayLabel(message.timestamp)
    }

    /// `today` / `yesterday` / `mon 18 aug` — lowercase, like the rest of the
    /// app's own chrome.
    static func dayLabel(_ date: Date) -> String {
        let cal = Calendar.current
        if cal.isDateInToday(date) { return "today" }
        if cal.isDateInYesterday(date) { return "yesterday" }
        let f = DateFormatter()
        f.locale = Locale.current
        f.setLocalizedDateFormatFromTemplate(
            cal.isDate(date, equalTo: Date(), toGranularity: .year) ? "EEEddMMM" : "EEEddMMMyyyy"
        )
        return f.string(from: date).lowercased()
    }

    init(friend: Friend, session: ChatSession, profileManager: ProfileManager? = nil) {
        self.friend = friend
        self.session = session
        self.profileManager = profileManager
        
        // Filter messages for this friend, IN THIS PROFILE. Matching on the
        // username alone merged the histories of two profiles that share a
        // contact into one thread. `profileID` is denormalised onto Message
        // precisely because a predicate can't walk `friend?.profile?.id`.
        let friendUsername = friend.username
        let profileID = friend.profile?.id ?? profileManager?.currentProfile?.id
        _messages = Query(filter: #Predicate<Message> { message in
            message.friend?.username == friendUsername && message.profileID == profileID
        }, sort: \Message.timestamp)
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // A brand-new channel with nothing in it yet: this is the moment to
            // compare safety numbers, and the only moment the user is thinking
            // about this specific contact. It disappears as soon as there is a
            // conversation, so it informs once instead of nagging forever.
            if friend.hasSession, !friend.isKeyVerified,
               !friend.isVanished, messages.isEmpty {
                HQBanner(
                    kind: .warning,
                    text: "verify \(friend.username)'s safety number to be sure it's them",
                    actionTitle: "verify",
                    action: { showingVerification = true }
                )
            }

            // The identity these messages were with no longer exists. Not "their
            // key changed" — a key IS an identity here, so there is nothing to
            // accept and nothing to re-pin. The history stays, read-only.
            if friend.isVanished {
                HQBanner(
                    kind: .warning,
                    text: "this identity is gone — @\(friend.username) now uses a different key",
                    actionTitle: "what happened",
                    action: { showingVerification = true }
                )
            }

            // Blocked, which is the same read-only state arrived at by the
            // opposite route: the user chose it, and the user can undo it. A
            // WORDED state rather than a disabled composer, per the design
            // system — a control that does nothing explains nothing.
            if friend.isBlocked {
                HQBanner(kind: .warning,
                         text: "you blocked @\(friend.username) — they can't reach you")
            }

            // Header
            HStack(spacing: 6) {
                HStack(spacing: 9) {
                    #if os(iOS)
                    // The system nav bar is hidden here (so is the tab bar), so
                    // this is the way back out of a conversation.
                    Button { dismiss() } label: {
                        Text("[<]")
                            .font(HQFont.mono(15, weight: .bold))
                            .foregroundColor(HQColor.green)
                            .hqTapTarget()
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("back to chats")
                    #endif

                    HQAvatar(name: friend.username, size: 38,
                             glow: HQColor.purple, isOnline: friend.isOnline)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(friend.username)
                            .font(HQFont.ui(16, weight: .semibold))
                            .foregroundColor(HQColor.textPrimary)
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)

                        HStack(spacing: 6) {
                            if friend.hasSession {
                                Button {
                                    showingVerification = true
                                } label: {
                                    HStack(spacing: 4) {
                                        Circle()
                                            .fill(friend.isOnline ? HQColor.green : Color.gray)
                                            .frame(width: 6, height: 6)
                                            .shadow(color: (friend.isOnline ? HQColor.green : .clear).opacity(0.9), radius: 4)
                                        if friend.isKeyVerified {
                                            Text("\(friend.isOnline ? "live" : "offline")·e2e·ok")
                                                .font(HQFont.mono(11, weight: .medium))
                                                .lineLimit(1)
                                                .foregroundColor(HQColor.green)
                                        } else {
                                            // Never green. This used to tint by
                                            // presence, so an ONLINE unverified
                                            // contact read exactly as reassuring
                                            // as a verified one — and key
                                            // substitution at first contact is
                                            // the one attack that survives all
                                            // the cryptography (threat model
                                            // §4.1). Unverified should look
                                            // unfinished, whoever is online.
                                            Text("\(friend.isOnline ? "live" : "offline")·e2e·unverified")
                                                .font(HQFont.mono(11, weight: .medium))
                                                .lineLimit(1)
                                                .foregroundColor(HQColor.warning)
                                        }
                                    }
                                }
                                .buttonStyle(.plain)
                                .accessibilityLabel(friend.isKeyVerified
                                    ? "\(friend.username) is \(friend.isOnline ? "online" : "offline"), encrypted, key verified"
                                    : "\(friend.username) is \(friend.isOnline ? "online" : "offline"), encrypted, key not verified")
                                .accessibilityHint("opens key verification")
                            } else {
                                HStack(spacing: 5) {
                                    Circle().fill(Color.gray).frame(width: 6, height: 6)
                                    // "not encrypted" was wrong twice over. There
                                    // is no unencrypted path — every message is
                                    // ratcheted, so nothing can go in the clear —
                                    // and it was drawn in the danger colour, which
                                    // read as a warning about a contact where
                                    // simply nobody had said anything yet.
                                    //
                                    // What is true: the session opens as part of
                                    // sending, so the channel is one message away.
                                    Text(friend.isReadyButUnopened
                                         ? "e2e·on first message"
                                         : "e2e·reconnecting")
                                        .font(HQFont.mono(12, weight: .medium))
                                        .lineLimit(1)
                                        .foregroundColor(HQColor.textMuted)
                                }
                                .accessibilityLabel(friend.isReadyButUnopened
                                    ? "encryption starts with your first message to \(friend.username)"
                                    : "reconnecting the encrypted session with \(friend.username)")
                            }
                        }
                    }
                }
                .layoutPriority(1)

                Spacer(minLength: 0)

                // Search toggle
                Button {
                    withAnimation { isSearching.toggle() }
                    if !isSearching { searchText = "" }
                } label: {
                    Image(systemName: isSearching ? "xmark" : "magnifyingglass")
                        .font(.system(size: 15))
                        .foregroundColor(HQColor.textSecond)
                        .hqTapTarget()
                }
                .buttonStyle(.plain)
                .accessibilityLabel(isSearching ? "close search" : "search this conversation")

                // Report, from the header.
                //
                // Until now the ONLY way to report was a long press on an
                // incoming bubble, and a long press is a bad thing to make the
                // only way: it is undiscoverable, it is unavailable when the
                // message you object to has scrolled off, and — reported from
                // use — it does not reliably fire on the newest messages, which
                // are the ones somebody upset is most likely to be reaching for.
                // Guideline 1.2 asks for a mechanism to report content, not for
                // a gesture, and this is a mechanism that cannot miss.
                //
                // No excerpt travels with it: this reports the CONVERSATION, and
                // the sheet says so where it would otherwise quote a message. A
                // report without message text is the metadata-only shape the
                // server has accepted since 006 — the reporter can still say what
                // happened in the note.
                //
                // A menu rather than a flag button, for two reasons: a one-tap
                // destructive action does not belong two points from `search` in
                // a header people touch constantly, and block belongs here too
                // when it arrives.
                Menu {
                    Button(role: .destructive) {
                        reportDraft = ReportDraft(excerpt: nil, messageId: nil)
                    } label: {
                        Label("report @\(friend.username)", systemImage: "flag")
                    }
                } label: {
                    Image(systemName: "ellipsis")
                        .font(.system(size: 15))
                        .foregroundColor(HQColor.textSecond)
                        .hqTapTarget()
                }
                .buttonStyle(.plain)
                .accessibilityLabel("more actions for this conversation")

                // Profile Selector — desktop only; on iOS the profile lives in
                // the friend-list top bar, so showing it here is redundant.
                #if os(macOS)
                if let profileManager = profileManager, !profileManager.profiles.isEmpty {
                    Menu {
                        ForEach(profileManager.profiles) { profile in
                            Button {
                                Task {
                                    do {
                                        try profileManager.switchToProfile(profile)
                                        // Trigger reconnection with new profile
                                        // The onChange handler in ContentView will handle this
                                    } catch {
                                        await MainActor.run {
                                            appError = .from(error)
                                        }
                                    }
                                }
                            } label: {
                                HStack {
                                    Text("@\(profile.username)")
                                    if profile.id == profileManager.currentProfile?.id {
                                        Image(systemName: "checkmark")
                                    }
                                }
                            }
                        }
                        
                        Divider()
                        
                        Button {
                            showingProfileSelector = true
                        } label: {
                            Label("Manage Profiles", systemImage: "person.2")
                        }
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: "person.circle.fill")
                                .font(.title3)
                            if let currentProfile = profileManager.currentProfile {
                                Text("@\(currentProfile.username)")
                                    .font(.caption)
                                    .fontWeight(.medium)
                            }
                            Image(systemName: "chevron.down")
                                .font(.caption2)
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.controlBackground.opacity(0.5))
                        .clipShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                #endif
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(HQColor.screen.opacity(0.5))
            .overlay(Rectangle().fill(HQColor.hairline).frame(height: 1), alignment: .bottom)
            .sheet(isPresented: $showingProfileSelector) {
                if let profileManager = profileManager {
                    ProfileSelectionView(profileManager: profileManager)
                        .environmentObject(appState)
                }
            }

            // In-chat search bar
            if isSearching {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(HQColor.textMuted)
                    TextField("search this conversation…", text: $searchText)
                        .textFieldStyle(.plain)
                        .foregroundColor(HQColor.textPrimary)
                    if !searchText.isEmpty {
                        Button {
                            searchText = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(HQColor.textMuted)
                                .hqTapTarget()
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("clear search")
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(HQColor.fillSoft)
                .overlay(Rectangle().stroke(Color.white.opacity(0.1), lineWidth: 1))
                .clipShape(Rectangle())
                .padding(.horizontal)
                .padding(.vertical, 6)
                .transition(.move(edge: .top).combined(with: .opacity))
            }

            // Messages List
            ScrollViewReader { proxy in
                ScrollView {
                    // Nothing at all until there is something to show. An empty
                    // conversation is self-explanatory — the composer is right
                    // there — and a placeholder in the middle of the screen only
                    // made a new chat look like an error state.
                    if !messages.isEmpty {
                        LazyVStack(alignment: .leading, spacing: 8) {
                            if !searchText.isEmpty && displayedMessages.isEmpty {
                                Text("no messages match \"\(searchText)\"")
                                    .font(HQFont.mono(12.5))
                                    .foregroundColor(HQColor.textMuted)
                                    .frame(maxWidth: .infinity)
                                    .padding(.top, 40)
                            }
                            ForEach(displayedMessages) { message in
                                // A message from ten minutes ago and one from
                                // last March used to be typographically
                                // identical — only a clock time, no date
                                // anywhere in the view.
                                if let day = daySeparator(before: message) {
                                    DaySeparator(text: day)
                                }
                                MessageBubble(
                                    message: message,
                                    onRetry: { retrySend(message) },
                                    // Incoming only. A report is about what
                                    // somebody else sent you.
                                    //
                                    // The text is COPIED here, while the finger
                                    // is still on the bubble, rather than held as
                                    // a reference the sheet dereferences later.
                                    onReport: message.isOutgoing ? nil : {
                                        reportDraft = ReportDraft(excerpt: message.content,
                                                                  messageId: message.messageId)
                                    })
                                    .id(message.id)
                            }
                        }
                        .padding()
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                // Two ways out of the keyboard, because there were none. The
                // composer takes focus and nothing on this screen gave it back:
                // no Done button, no tap-away, and scrolling did not dismiss —
                // so the only way to see the bottom of your own conversation was
                // to leave it and come back in.
                //
                // Drag-to-dismiss is the one people try first, and it is also the
                // one that fixes reaching the newest message: the keyboard is
                // exactly what was covering it.
                .scrollDismissesKeyboard(.interactively)
                // …and a plain tap on the transcript. This does not steal the
                // bubbles' own gestures: a long press belongs to the context
                // menu and the retry line is a Button, and a child recognizer
                // wins over a parent's tap.
                .onTapGesture { composerFocused = false }
                .onChange(of: messages.count) { _, _ in
                    if let lastMessage = messages.last {
                        withAnimation {
                            proxy.scrollTo(lastMessage.id, anchor: .bottom)
                        }
                    }
                }
                // Focusing the composer shrinks this scroll view by the height of
                // the keyboard. The content stays anchored where it was, so the
                // newest messages end up BELOW the visible area — present, and
                // unreachable without scrolling. Follow the bottom instead.
                //
                // Delayed for the same reason .onAppear below is: the scroll has
                // to happen after the keyboard's animation has resized us, not
                // against the layout we are being moved away from.
                .onChange(of: composerFocused) { _, focused in
                    guard focused, let lastMessage = messages.last else { return }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                        withAnimation {
                            proxy.scrollTo(lastMessage.id, anchor: .bottom)
                        }
                    }
                }
                .onAppear {
                    // Scroll to bottom when view appears
                    if let lastMessage = messages.last {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                            withAnimation {
                                proxy.scrollTo(lastMessage.id, anchor: .bottom)
                            }
                        }
                    }
                }
            }
            
            // Input Area
            //
            // Always the composer. There is no "waiting for a channel" state to
            // gate it on any more, and gating on one DEADLOCKED the app: a
            // session opens when you send the first message, so hiding the
            // composer until a session existed meant it never could. The screen
            // sat on "exchanging keys — you can send in a moment" forever, and
            // the moment could not arrive.
            //
            // Whether the peer can actually be reached is not knowable until we
            // try (they may have published no prekeys), so it is reported when
            // the send fails rather than guessed at beforehand.
            composerBar
            .padding(12)
            .background(HQColor.screen.opacity(0.5))
            .overlay(
                Rectangle()
                    .fill(HQColor.hairline)
                    .frame(height: 1),
                alignment: .top
            )
            .sheet(isPresented: $showingVerification) {
                KeyVerificationView(
                    friend: friend,
                    myPublicKey: profileManager?.currentProfile?.publicKey,
                    onMarkVerified: {
                        friend.keyVerified = true
                        try? modelContext.save()
                    },
                    onClearVerification: {
                        friend.keyVerified = false
                        try? modelContext.save()
                    },
                    onRotateKeys: {
                        let svc = FriendService(session: session, modelContext: modelContext)
                        svc.setModelContext(modelContext)
                        svc.forceRatchetStep(friend: friend)
                    }
                )
            }

        // `item:`, not a derived `isPresented:` — the difference is where the
        // content comes from. The old form rebuilt a Bool out of the target and
        // then read that target AGAIN inside the builder, and SwiftUI evaluates
        // that builder on its own schedule: any evaluation landing before the
        // state does produces a sheet with nothing in it and no way to tell why.
        // `item:` hands the value to the closure, so the sheet cannot be
        // presented without the thing it is about.
        //
        // Safe to key on now that the item is a `ReportDraft`: its id is a UUID
        // this screen mints, not an identifier the persistent store owns and may
        // reissue. See ReportDraft's own note.
        .sheet(item: $reportDraft) { draft in
            ReportSheet(friend: friend, draft: draft, session: session) {
                // A block leaves this conversation read-only and there is
                // nothing further to do on it, so the screen closes behind
                // the sheet rather than sitting on a composer that refuses.
                if friend.isBlocked { dismiss() }
            }
        }
        .hqError($appError)
        .hqScreenBackground()
        #if os(iOS)
        // A conversation is a full screen: the tab bar underneath it was both
        // wasted space and a way to leave mid-message. The custom header above
        // carries the back control.
        .toolbar(.hidden, for: .tabBar)
        // Hiding the bar is enough — `navigationBarBackButtonHidden` would also
        // take the interactive edge-swipe back with it, and the swipe is how
        // most people leave a conversation.
        .toolbar(.hidden, for: .navigationBar)
        // …and the same swipe from anywhere on the screen, not only the left
        // edge. With the nav bar hidden the edge gesture is invisible, so the
        // only discoverable exit was the `[<]` glyph at the top-left — the
        // furthest point from a thumb holding the phone.
        .hqSwipeNavigation(onBack: { dismiss() })
        #endif
        // Opening a thread is the moment to ask: the rows below are sealed, and
        // this costs one prompt for all of them rather than one each.
        .task { await messageKeys.unlock() }
        .onAppear {
            // Reading it is reading it: clear the unread badges for this thread,
            // and suppress banners for messages that land while it's open.
            NotificationService.shared.visibleConversation = friend.username
            NotificationService.shared.markRead(friend: friend, modelContext: modelContext)
        }
        .onDisappear {
            if NotificationService.shared.visibleConversation == friend.username {
                NotificationService.shared.visibleConversation = nil
            }
        }
        .onChange(of: messages.count) { _, _ in
            NotificationService.shared.markRead(friend: friend, modelContext: modelContext)
        }
        // The active-call screen is presented globally (see IncomingCallOverlay)
        // so it works for both the caller and the callee on any screen.
    }

    // MARK: Composer + recording bars

    /// Stands in for the composer until the secure channel is up.

    private var iconTint: Color { friend.hasSession ? HQColor.green : HQColor.textFaint }

    @ViewBuilder
    private var composerBar: some View {
        // A vanished identity is the ONE case where there is nothing to type
        // into. Not "no session yet" — gating on that is what deadlocked every
        // chat, because sending is what OPENS a session. This is the opposite
        // situation: the identity is gone from the server, so there is no key to
        // encapsulate to and no topic anyone holds a grant on. A composer here
        // could only ever fail.
        if friend.isVanished {
            vanishedComposer
        } else if friend.isBlocked {
            blockedComposer
        } else {
            liveComposer
        }
    }

    /// The other read-only case. Sending would be refused by the broker anyway —
    /// blocking revokes both members' grant on the conversation topic — so the
    /// composer says what happened instead of failing on send.
    private var blockedComposer: some View {
        VStack(spacing: 4) {
            Text("you blocked this contact")
                .font(HQFont.mono(12, weight: .semibold))
                .foregroundColor(HQColor.textMuted)
            Text("nothing can be sent to @\(friend.username), and they can't add you again. unblock them from contacts to start over.")
                .font(HQFont.ui(12))
                .foregroundColor(HQColor.textDim)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
    }

    private var vanishedComposer: some View {
        VStack(spacing: 4) {
            Text("you can't reply to this identity")
                .font(HQFont.mono(12, weight: .semibold))
                .foregroundColor(HQColor.textMuted)
            Text("@\(friend.username) signs in with a different key now, which makes them a separate contact. Open that one to keep talking.")
                .font(HQFont.ui(12))
                .foregroundColor(HQColor.textDim)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
    }

    private var liveComposer: some View {
        // One row: the field this screen exists for, and send. Attachments come
        // back when images do (a later phase) — until then the row is the field.
        HStack(alignment: .bottom, spacing: 8) {
            HStack(alignment: .bottom, spacing: 8) {
                Text(">")
                    .font(HQFont.mono(15, weight: .bold))
                    .foregroundColor(composerFocused ? HQColor.greenBright : HQColor.textDim)
                    .padding(.bottom, 1)
                    .accessibilityHidden(true)

                TextField("type a message…", text: $messageText, axis: .vertical)
                    .textFieldStyle(.plain)
                    .font(HQFont.ui(14.5))
                    .foregroundColor(HQColor.textPrimary)
                    .lineLimit(1...5)
                    .focused($composerFocused)
                    .accessibilityLabel("message")
            }
            .padding(.horizontal, 11)
            .padding(.vertical, 9)
            .frame(maxWidth: .infinity)
            .background(Color.white.opacity(composerFocused ? 0.05 : 0.03))
            .overlay(alignment: .bottom) {
                Rectangle()
                    .fill(composerFocused ? HQColor.green : Color.white.opacity(0.14))
                    .frame(height: composerFocused ? 1.5 : 1)
                    .shadow(color: composerFocused ? HQColor.green.opacity(0.7) : .clear, radius: 5)
            }
            .animation(.easeOut(duration: 0.16), value: composerFocused)
            .disabled(isSending)

            sendButton
        }
    }

    @ViewBuilder
    private var sendButton: some View {
        let hasText = !messageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        Button {
            sendMessage()
        } label: {
            Group {
                if isSending {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "paperplane.fill")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundColor(HQColor.onGreen)
                }
            }
            .frame(width: 44, height: 44)
            .background(LinearGradient(colors: [HQColor.greenBright, HQColor.greenDeep],
                                       startPoint: .topLeading, endPoint: .bottomTrailing))
            .clipShape(Rectangle())
            .shadow(color: HQColor.green.opacity(0.6), radius: 12)
            .opacity(isSending ? 0.4 : 1)
        }
        .buttonStyle(.plain)
        .disabled(isSending || !hasText)
        .opacity(hasText ? 1 : 0.45)
        .accessibilityLabel("send")
    }

    private func sendMessage() {
        // Only the text is required. Sending is what OPENS the session — the
        // first message carries the handshake — so refusing to send without one
        // would refuse the exact case v2 exists to support: writing to a contact
        // who has never been online at the same time as you. `deliver` surfaces
        // the failure if the peer has published no prekeys.
        guard !messageText.isEmpty else { return }

        let text = messageText
        let messageId = UUID().uuidString

        // Insert the row *before* sending. Previously the message was only
        // created after the send succeeded, so a failed send left no trace at
        // all: the composer kept the text and the user got a raw transport
        // string in an alert, with nothing to retry.
        let message = Message(content: text, isOutgoing: true, friend: friend,
                              messageId: messageId, deliveryStatus: .sending)
        modelContext.insert(message)
        save()

        messageText = ""
        isSending = true

        Task {
            do {
                try await deliver(text: text, messageId: messageId)
                await MainActor.run {
                    // advance, not assign: the delivery receipt often beats this
                    // continuation back, and it must not be overwritten.
                    message.advanceDelivery(to: .sent)
                    save()
                    isSending = false
                }
            } catch {
                await MainActor.run {
                    message.advanceDelivery(to: .failed)
                    save()
                    isSending = false
                    appError = .from(error)
                }
            }
        }
    }

    /// Re-send a message that previously failed, reusing its id so a delivery
    /// receipt still correlates.
    private func retrySend(_ message: Message) {
        guard message.deliveryStatus == .failed else { return }
        let text = message.content
        let messageId = message.messageId ?? UUID().uuidString

        message.deliveryStatus = .sending
        save()

        Task {
            do {
                try await deliver(text: text, messageId: messageId)
                await MainActor.run {
                    message.advanceDelivery(to: .sent)
                    save()
                }
            } catch {
                await MainActor.run {
                    message.advanceDelivery(to: .failed)
                    save()
                    appError = .from(error)
                }
            }
        }
    }

    /// Encrypt and transmit one message. Shared by the first attempt and any
    /// retry, so both paths advance the ratchet identically.
    ///
    /// One path now. v1 branched here: a per-message ratchet key at epoch ≥ 1,
    /// and the STATIC channel key otherwise — and since nothing installed an
    /// epoch until 100 messages had been sent or the user pressed a button, the
    /// static branch was where most conversations lived their whole lives. That
    /// branch is gone, which is what closes KM-5.
    ///
    /// The session opens itself on the first send, so this also works when the
    /// peer has never been online: the frame carries the handshake.
    private func deliver(text: String, messageId: String) async throws {
        let envelope = try await session.sealMessage(text, to: friend, msgId: messageId)
        // The payload is the AES-GCM base64 directly — no outer per-message HQC
        // (§KM-1 step 5) — and the header travels bound to it as AAD, so the
        // broker can neither read a byte of it nor rewrite which key opens it.
        session.publish(envelope, to: friend)
    }

    /// Persist, surfacing failures instead of swallowing them with `try?`.
    private func save() {
        do {
            try modelContext.save()
        } catch {
            appError = .unknown("Couldn't save to this device: \(error.localizedDescription)")
        }
    }
}

/// The one place a message bubble's surface is defined, so bubbles cannot drift
/// apart as new kinds are added back (photos, voice notes).
enum HQBubble {
    static func fill(outgoing: Bool) -> AnyShapeStyle {
        outgoing
        ? AnyShapeStyle(HQColor.green.opacity(0.10))
        : AnyShapeStyle(Color.white.opacity(0.035))
    }

    static func stroke(outgoing: Bool) -> Color {
        outgoing ? HQColor.green.opacity(0.22) : Color.white.opacity(0.08)
    }
}

struct MessageBubble: View {
    let message: Message
    /// Called when the user taps a failed message. Nil where retry doesn't
    /// apply (previews, read-only contexts).
    var onRetry: (() -> Void)?
    /// Report this message. Nil on outgoing messages and in previews — there is
    /// nobody to report for something you sent yourself.
    ///
    /// This is the app's FIRST context menu on a bubble, which is why it holds
    /// one item and not a menu of them: the design system says extend what
    /// exists before adding, and what exists here is nothing. Copy, forward and
    /// the rest belong in this menu when they arrive, not in a second gesture.
    var onReport: (() -> Void)?
    
    /// What the delivery glyph means, for VoiceOver — it is otherwise a shape
    /// with no name, on the thing a sender looks at most.
    private var deliveryDescription: String {
        switch message.deliveryStatus {
        case .sending:   return "sending"
        case .sent:      return "sent"
        case .delivered: return "delivered"
        case .queued:    return "queued — they are offline"
        case .failed:    return "not sent"
        }
    }

    /// Delivery state glyph shown after the timestamp on outgoing messages.
    @ViewBuilder
    private var deliveryIcon: some View {
        switch message.deliveryStatus {
        case .sending:
            Image(systemName: "clock").font(.caption2).foregroundColor(HQColor.textDim)
        case .sent:
            Image(systemName: "checkmark").font(.caption2).foregroundColor(HQColor.textSecond)
        case .delivered:
            // Was system blue — the one primary-blue pixel in a green/violet
            // app, on the glyph people look at most.
            Image(systemName: "checkmark.circle.fill").font(.caption2).foregroundColor(HQColor.green)
        case .queued:
            Image(systemName: "clock.badge.questionmark")
                .font(.caption2)
                .foregroundColor(HQColor.warning)
        case .failed:
            Image(systemName: "exclamationmark.circle.fill")
                .font(.caption2)
                .foregroundColor(HQColor.danger)
        }
    }
    
    /// The bubble, and — the part that is not decoration — the area you can
    /// actually press.
    ///
    /// A bubble hugs its text, so "ok" drew one about 46×37pt. That is under
    /// Apple's 44pt minimum on the axis that matters, and a long press is far
    /// less forgiving than a tap: the finger has to stay inside the target for
    /// half a second, so a short message was genuinely hard to report and a
    /// two-character one was luck. The artwork is unchanged — the frame below
    /// only adds transparent area, exactly as `hqTapTarget()` does for the
    /// icon-only controls elsewhere.
    ///
    /// Not `hqTapTarget()` itself, though, because that one centres what it
    /// grows: a short bubble would sit 2pt off the edge its neighbours line up
    /// against. The alignment here keeps every bubble flush on its own side.
    private var bubble: some View {
        Text(message.content)
            .font(HQFont.ui(14.5))
            .foregroundColor(message.isOutgoing ? HQColor.inkOnGreenBubble : HQColor.inkOnGreyBubble)
            .padding(.horizontal, 13)
            .padding(.vertical, 10)
            // Quieter than it was. The bubbles carried a full-strength
            // 1pt outline in green or violet, so a page of chat read as
            // a stack of framed boxes competing with the words inside
            // them. Direction is still unmistakable — warm fill on the
            // right, neutral on the left — but the frame recedes.
            .background(HQBubble.fill(outgoing: message.isOutgoing))
            .clipShape(Rectangle())
            .overlay(
                Rectangle()
                    .stroke(HQBubble.stroke(outgoing: message.isOutgoing), lineWidth: 1)
            )
            .frame(minWidth: 44, minHeight: 44,
                   alignment: message.isOutgoing ? .trailing : .leading)
            // Without this the added area is transparent to touch as well as to
            // the eye, and growing the frame would have bought nothing.
            .contentShape(Rectangle())
    }

    var body: some View {
        HStack {
            if message.isOutgoing {
                Spacer()
            }

            VStack(alignment: message.isOutgoing ? .trailing : .leading, spacing: 4) {
                // The menu is attached ONLY when there is something in it.
                // `.contextMenu` with an empty body still takes the long press —
                // the haptic fires, the screen dims, and an empty tray animates
                // in — so on your own messages the gesture looked broken rather
                // than inapplicable. Outgoing bubbles now simply do not respond,
                // which is the honest answer: a report is about what somebody
                // else sent you.
                if let onReport {
                    bubble.contextMenu {
                        Button(role: .destructive, action: onReport) {
                            Label("report", systemImage: "flag")
                        }
                    }
                } else {
                    bubble
                }

                HStack(spacing: 4) {
                    Text(message.timestamp, style: .time)
                        .font(HQFont.mono(10))
                        .foregroundColor(HQColor.textDim)
                    if message.isOutgoing {
                        deliveryIcon
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel(message.isOutgoing
                    ? "\(message.timestamp.formatted(date: .omitted, time: .shortened)), \(deliveryDescription)"
                    : message.timestamp.formatted(date: .omitted, time: .shortened))

                // A failed message is only useful if it can be sent again.
                if message.isOutgoing, message.deliveryStatus == .failed, let onRetry {
                    Button(action: onRetry) {
                        HStack(spacing: 4) {
                            Image(systemName: "arrow.clockwise")
                            Text("not sent · tap to retry")
                        }
                        .font(HQFont.mono(10, weight: .medium))
                        .foregroundColor(HQColor.danger)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("retry sending this message")
                }
            }
            .frame(maxWidth: 300, alignment: message.isOutgoing ? .trailing : .leading)
            
            if !message.isOutgoing {
                Spacer()
            }
        }
    }
}


/// Report one message to whoever runs this server.
///
/// App Store Guideline 1.2 asks a user-generated-content app for a mechanism to
/// report objectionable content. This is it, and two sentences on this screen
/// carry the whole honesty of the feature — both are said in the copy, not only
/// in a comment:
///
///   * sending a report **uploads that message's text to the server**. It is the
///     one thing in this app that leaves the device readable, and it happens
///     because the user asked for it, not as a side effect of tapping "report".
///   * a reported excerpt is **not verifiable**. It is the reporter's own copy.
///     Nothing on the server can tell a real one from an invented one, and
///     implying otherwise would be the single dishonest sentence in the product.
///
/// The optional block is here because the two belong together at the moment
/// somebody is upset: reporting asks a stranger to act eventually, blocking acts
/// now. ORDER MATTERS — the server refuses a report from someone who is no
/// longer in the conversation, and blocking ends it, so the report goes first.
struct ReportSheet: View {
    let friend: Friend
    /// What is being reported: one message, or — from the header — the
    /// conversation. A snapshot rather than a live model; see `ReportDraft`.
    let draft: ReportDraft
    let session: ChatSession
    let onFinished: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var category = "harassment"
    @State private var note = ""
    @State private var alsoBlock = true
    @State private var sending = false
    @State private var appError: AppError?

    /// One row of the picker. A named struct rather than a tuple because
    /// `ForEach(_:id:)` needs a key path and Swift has none into a tuple —
    /// `\.0` does not compile.
    private struct Category: Identifiable {
        let id: String       // exactly what goes on the wire
        let label: String    // what the user reads
    }

    /// The same vocabulary the server accepts (`DB.reportCategories`) and the
    /// column constrains. A category this list invents is a 400, so the two
    /// lists agreeing is not cosmetic.
    private static let categories: [Category] = [
        Category(id: "harassment", label: "harassment or bullying"),
        Category(id: "spam", label: "spam or a scam"),
        Category(id: "sexual", label: "sexual content"),
        Category(id: "violence", label: "violence or threats"),
        Category(id: "csae", label: "child sexual abuse or exploitation"),
        Category(id: "other", label: "something else"),
    ]

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button("cancel") { dismiss() }
                    .buttonStyle(.plain)
                    .font(HQFont.ui(15))
                    .foregroundColor(HQColor.textSecond)
                Spacer()
                Text("report message")
                    .font(HQFont.ui(16, weight: .bold))
                    .foregroundColor(.white)
                Spacer()
                Button(sending ? "sending…" : "send") { send() }
                    .buttonStyle(.plain)
                    .font(HQFont.ui(15, weight: .semibold))
                    .foregroundColor(sending ? HQColor.textOff : HQColor.danger)
                    .disabled(sending)
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 16)
            .overlay(Rectangle().fill(HQColor.hairline).frame(height: 1), alignment: .bottom)

            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    // One message, or the conversation. The sheet must not quote
                    // something it was not given: a header report carries no
                    // excerpt, and an empty box under "the message" would read as
                    // a message that was blank rather than as one that was never
                    // part of this report.
                    if let excerpt = draft.excerpt {
                        HQFieldLabel(text: "the message").padding(.bottom, 9)
                        Text(excerpt)
                            .font(HQFont.ui(13.5))
                            .foregroundColor(HQColor.textOnCard)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(13)
                            // A FLOOR, not a height. Hugging the text made this
                            // box one line plus padding for "ok" or "stop" — a
                            // strip thinner than its own label, reading as a
                            // caption rather than as the thing being reported,
                            // and short messages are most of what gets reported.
                            // Scaled for the same reason HQTextField's minHeight
                            // is: a fixed number clips at larger Dynamic Type
                            // sizes. .topLeading so a short message starts where
                            // a long one does; plain .leading would centre it.
                            .frame(maxWidth: .infinity,
                                   minHeight: HQFont.scaled(64),
                                   alignment: .topLeading)
                            .background(Color.white.opacity(0.03))
                            .overlay(Rectangle().stroke(Color.white.opacity(0.08), lineWidth: 1))
                    } else {
                        HQFieldLabel(text: "what you're reporting").padding(.bottom, 9)
                        Text("this conversation with @\(friend.username). no message text is "
                             + "attached — say what happened below, and name a message if you can.")
                            .font(HQFont.ui(13.5))
                            .foregroundColor(HQColor.textOnCard)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(13)
                            .frame(maxWidth: .infinity, alignment: .topLeading)
                            .background(Color.white.opacity(0.03))
                            .overlay(Rectangle().stroke(Color.white.opacity(0.08), lineWidth: 1))
                    }

                    HQFieldLabel(text: "what happened").padding(.top, 26).padding(.bottom, 9)
                    VStack(spacing: 9) {
                        ForEach(Self.categories) { option in
                            Button { category = option.id } label: {
                                HStack(spacing: 11) {
                                    Image(systemName: category == option.id
                                          ? "largecircle.fill.circle" : "circle")
                                        .font(.system(size: 14))
                                        .foregroundColor(category == option.id ? HQColor.danger : HQColor.textDim)
                                        .accessibilityHidden(true)
                                        .frame(width: 30, height: 30)
                                    Text(option.label)
                                        .font(HQFont.ui(13.5))
                                        .foregroundColor(HQColor.textPrimary)
                                    Spacer(minLength: 0)
                                }
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel(option.label)
                            .accessibilityAddTraits(category == option.id ? [.isSelected] : [])
                        }
                    }

                    HQFieldLabel(text: "anything to add (optional)")
                        .padding(.top, 26).padding(.bottom, 9)
                    HQTextField(placeholder: "what should we know?", text: $note)

                    // The consent, said plainly, above the button that acts on
                    // it. Everything else in this app keeps message text on the
                    // device; this is the one path that does not, and a user who
                    // does not know that cannot be said to have consented.
                    HStack(alignment: .top, spacing: 11) {
                        Image(systemName: "arrow.up.doc")
                            .font(.system(size: 14))
                            .foregroundColor(HQColor.warning)
                            .accessibilityHidden(true)
                            .frame(width: 30, height: 30)
                        // Two different promises, because two different things
                        // are sent. Leaving the message-text wording on a report
                        // that carries no message would be the one dishonest
                        // sentence in the feature — in the direction of claiming
                        // we took MORE than we did, which is the less harmful
                        // direction and still not true.
                        VStack(alignment: .leading, spacing: 4) {
                            Text(draft.excerpt == nil
                                 ? "this sends what you type to the server"
                                 : "this sends the message text to the server")
                                .font(HQFont.ui(13, weight: .semibold))
                                .foregroundColor(HQColor.textOnCard)
                            Text(draft.excerpt == nil
                                 ? "no message text is attached to this one — only your note, the "
                                   + "category, and which conversation it is about. we cannot check "
                                   + "whether a report is real, so it is read as what you handed in. "
                                   + "it is deleted after 90 days."
                                 : "it is the only thing in this app that does. we cannot check whether "
                                   + "an excerpt is real — anyone could type anything here — so it is "
                                   + "read as what you handed in, not as proof of what was said. "
                                   + "it is deleted after 90 days.")
                                .font(HQFont.ui(11.5))
                                .foregroundColor(HQColor.textMuted)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(14)
                    .background(Color.white.opacity(0.02))
                    .overlay(Rectangle().stroke(HQColor.warning.opacity(0.25), lineWidth: 1))
                    .padding(.top, 26)

                    Button { alsoBlock.toggle() } label: {
                        HStack(alignment: .top, spacing: 11) {
                            Image(systemName: alsoBlock ? "checkmark.square.fill" : "square")
                                .font(.system(size: 14))
                                .foregroundColor(alsoBlock ? HQColor.danger : HQColor.textDim)
                                .accessibilityHidden(true)
                                .frame(width: 30, height: 30)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("also block @\(friend.username)")
                                    .font(HQFont.ui(13.5, weight: .semibold))
                                    .foregroundColor(HQColor.textPrimary)
                                Text("they can no longer reach you, and cannot add you again. "
                                     + "your messages stay on this device.")
                                    .font(HQFont.ui(11.5))
                                    .foregroundColor(HQColor.textMuted)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 0)
                        }
                    }
                    .buttonStyle(.plain)
                    .hqTapTarget()
                    .accessibilityLabel("also block \(friend.username)")
                    .accessibilityAddTraits(alsoBlock ? [.isSelected] : [])
                    .padding(.top, 20)
                }
                .padding(.horizontal, 22)
                .padding(.top, 26)
                .padding(.bottom, 40)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .hqScreenBackground()
        .sheetSizing(minHeight: 620)
        .hqError($appError)
    }

    private func send() {
        sending = true
        let mine = session.myID
        let peer = friend.peerID
        Task {
            do {
                // REPORT FIRST. The server requires the reporter to still be a
                // member of the conversation, and blocking tears it down — so
                // the other order files nothing and looks like it worked.
                _ = try await session.api.report(
                    conversation: MQTTTopics.friendshipHash(mine, peer),
                    peer: peer,
                    category: category,
                    note: note.isEmpty ? nil : note,
                    // Both nil for a header report: the server has accepted a
                    // metadata-only report since 006, and optionalString treats
                    // absent and null alike.
                    excerpt: draft.excerpt,
                    messageId: draft.messageId)
                if alsoBlock {
                    try await session.api.block(peer: peer)
                    await MainActor.run { friend.blockedAt = Date() }
                }
                await MainActor.run {
                    sending = false
                    onFinished()
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    sending = false
                    appError = .from(error)
                }
            }
        }
    }
}

#Preview {
    let container = try! ModelContainer(for: Friend.self, Message.self)
    let previewKey = Data(count: 7237)
    let friend = Friend(username: "alice",
                        peerID: PeerID.from(publicKey: previewKey),
                        publicKey: previewKey)
    return ChatView(friend: friend, session: ChatSession())
        .modelContainer(container)
}

