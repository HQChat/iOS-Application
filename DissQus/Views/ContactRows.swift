//
//  ContactRows.swift
//  DissQus
//
//  Row components shared by the macOS friend list and the iOS Chats/Contacts
//  tabs, so the two platforms cannot drift apart visually.
//

import SwiftUI

/// One contact: avatar, name, and either its invite state or its live
/// presence/encryption state. Actions are injected so the same row serves the
/// conversation list, the contact list, and the pending-invite section.
struct ContactRow: View {
    let friend: Friend
    /// Conversation rows (the Chats tab) show the last message and when it
    /// arrived, and carry the unread badge. Contact rows (the Contacts tab)
    /// show identity and presence instead: the same row used to do both, so an
    /// unread count appeared in Contacts, where tapping cannot open the thread.
    var style: Style = .contact
    var onAccept: (() -> Void)?
    var onCancel: (() -> Void)?

    enum Style { case conversation, contact }

    /// Unread incoming messages in this conversation, for the row badge.
    private var unreadCount: Int { (friend.messages ?? []).filter(\.isUnread).count }

    /// The most recent message either way, for the preview line.
    private var lastMessage: Message? {
        (friend.messages ?? []).max(by: { $0.timestamp < $1.timestamp })
    }

    /// One line of the last message — the thing people actually scan a
    /// conversation list for. V0 carries text only; when photos and voice notes
    /// come back this is where they get described rather than dumped (their
    /// stored content is base64).
    private var preview: String? {
        guard let m = lastMessage else { return nil }
        let body = m.content.replacingOccurrences(of: "\n", with: " ")
        return m.isOutgoing ? "you: \(body)" : body
    }

    /// Compact arrival stamp: a time today, a weekday this week, else a date.
    private var stamp: String? {
        guard let date = lastMessage?.timestamp else { return nil }
        let cal = Calendar.current
        let f = DateFormatter()
        f.locale = Locale.current
        if cal.isDateInToday(date) {
            f.setLocalizedDateFormatFromTemplate("jm")
        } else if let week = cal.date(byAdding: .day, value: -6, to: Date()), date > week {
            f.setLocalizedDateFormatFromTemplate("EEE")
        } else {
            f.setLocalizedDateFormatFromTemplate("ddMMM")
        }
        return f.string(from: date).lowercased()
    }

    var body: some View {
        HStack(spacing: 12) {
            HQAvatar(name: friend.username, size: 44,
                     glow: HQColor.purple, isOnline: friend.isOnline)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(friend.username)
                        .font(HQFont.ui(16, weight: .semibold))
                        .foregroundColor(HQColor.textPrimary)
                    if style == .contact {
                        // ID stamp: the same at-a-glance identity check the
                        // search rows show, so a contact is never just a name.
                        // A conversation row spends that space on the message.
                        //
                        // The ID, not the key: it is what the graph and the
                        // topics name this person by, it is what a second
                        // contact with the same handle differs in, and it is
                        // short enough to read out loud.
                        Text(friend.peerID.prefix(6))
                            .font(HQFont.mono(10))
                            .foregroundColor(HQColor.textFaint)
                    }
                    Spacer(minLength: 4)
                    if style == .conversation, let stamp {
                        Text(stamp)
                            .font(HQFont.mono(10.5))
                            .foregroundColor(HQColor.textDim)
                    }
                }

                if style == .conversation, let preview {
                    Text(preview)
                        .font(HQFont.ui(13))
                        .foregroundColor(unreadCount > 0 ? HQColor.textSecond : HQColor.textMuted)
                        .lineLimit(1)
                        .truncationMode(.tail)
                } else {
                    statusLine
                }
            }

            Spacer(minLength: 6)

            // The badge belongs where it can be acted on. `ContactRow` is shared
            // between both tabs, so an unread count used to show in Contacts too.
            if style == .conversation, unreadCount > 0 {
                Text("\(unreadCount)")
                    .font(HQFont.mono(11, weight: .bold))
                    .foregroundColor(HQColor.onGreen)
                    .padding(.horizontal, 6).padding(.vertical, 3)
                    .background(HQColor.greenBright)
                    .shadow(color: HQColor.green.opacity(0.6), radius: 5)
                    .accessibilityLabel("\(unreadCount) unread")
            }

            if friend.inviteStatus == .inviteReceived, let onAccept {
                Button(action: onAccept) {
                    Text("accept")
                        .font(HQFont.ui(13, weight: .semibold))
                        .foregroundColor(HQColor.onGreen)
                        .padding(.horizontal, 14).padding(.vertical, 7)
                        .background(LinearGradient(colors: [HQColor.greenBright, HQColor.greenDeep],
                                                   startPoint: .topLeading, endPoint: .bottomTrailing))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                }
                .buttonStyle(.plain)
            } else if friend.inviteStatus == .inviteSent, let onCancel {
                // An invite you sent used to be a dead end — visible but with no
                // way to take it back.
                Button(action: onCancel) {
                    Text("cancel")
                        .font(HQFont.mono(11, weight: .semibold))
                        .foregroundColor(HQColor.textMuted)
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .overlay(RoundedRectangle(cornerRadius: 3)
                            .stroke(HQColor.hairline, lineWidth: 1))
                }
                .buttonStyle(.plain)
                .accessibilityLabel("cancel the invite to \(friend.username)")
            }
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private var statusLine: some View {
        switch friend.inviteStatus {
        case .inviteSent:
            Text("invite sent")
                .font(HQFont.mono(11.5, weight: .medium))
                .foregroundColor(HQColor.warning)
        case .inviteReceived:
            Text("wants to connect")
                .font(HQFont.mono(11.5, weight: .medium))
                .foregroundColor(HQColor.purpleLight)
        case .accepted, .none:
            // A vanished identity has no presence and no session to describe —
            // it is gone. Showing "offline · setting up" for it was the bug this
            // row had all along: key-change state was visible ONLY after opening
            // the thread, so a contact list could show a perfectly ordinary row
            // for someone who cannot be written to at all.
            if friend.isVanished {
                HStack(spacing: 5) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 9))
                    Text("identity gone")
                }
                .font(HQFont.mono(11.5, weight: .medium))
                .foregroundColor(HQColor.warning)
                .accessibilityLabel("\(friend.username)'s identity no longer exists")
            } else {
                HStack(spacing: 5) {
                    Text(friend.isOnline ? "live" : "offline")
                        .foregroundColor(friend.isOnline ? HQColor.green : HQColor.textMuted)
                    if friend.hasSession {
                        Text("· e2e").foregroundColor(HQColor.green)
                    } else if !friend.hasPinnedKey {
                        // The directory ships ids; the key is fetched and checked
                        // against the id separately. Worth distinguishing from
                        // "setting up", which is about the session.
                        Text("· awaiting key").foregroundColor(HQColor.textDim)
                    } else if friend.isReadyButUnopened {
                        // NOT "setting up". Nothing is being set up: the key is
                        // pinned, the topics are subscribed, and the session
                        // opens as part of sending the first message. The old
                        // label described v1, where a handshake really was in
                        // flight, and in v2 it left both people waiting for
                        // something that never arrives on its own — which is
                        // exactly what "we accepted and both sides say setting
                        // up" was.
                        Text("· ready").foregroundColor(HQColor.textDim)
                    } else {
                        // Messages on record but no session: one existed and is
                        // gone. Same remedy — the next message re-opens it — but
                        // worth not calling that "ready".
                        Text("· reconnecting").foregroundColor(HQColor.textDim)
                    }
                }
                .font(HQFont.mono(11.5, weight: .medium))
            }
        }
    }
}

/// Where a search result already stands relative to you. A result used to be
/// either "invite them" or "invited" — so someone who was *already* a contact
/// still showed an add button, and tapping it re-sent an invite the server then
/// rejected.
enum ContactRelation {
    /// Not connected in any way — the only state with an add button.
    case none
    /// You already have them; the row says so and offers nothing to tap.
    case added
    /// You invited them and they haven't answered.
    case invited
    /// They invited you — accepting lives in Contacts, not here.
    case awaitingYou
    /// Your own account.
    case you
}

/// A search result for someone who isn't a contact yet. Adding is one tap —
/// it used to pre-fill a modal sheet that the user then had to submit.
struct UserSearchRow: View {
    let user: UserListItem
    /// How this person already relates to you, which decides whether the row
    /// offers an action or just states the fact.
    var relation: ContactRelation = .none
    var onAdd: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            HQAvatar(name: user.username, size: 40, glow: HQColor.purple)

            VStack(alignment: .leading, spacing: 3) {
                Text("@\(user.username)")
                    .font(HQFont.ui(15, weight: .semibold))
                    .foregroundColor(HQColor.textPrimary)
                Text("id \(user.id.prefix(5))…")
                    .font(HQFont.mono(11))
                    .foregroundColor(HQColor.textFaint)
                    .lineLimit(1)
            }

            Spacer()

            switch relation {
            case .added:
                // The whole point of the tick: you can stop wondering whether
                // you already added them.
                HStack(spacing: 5) {
                    Image(systemName: "checkmark")
                        .font(.system(size: 9, weight: .heavy))
                        .foregroundColor(HQColor.onGreen)
                        .frame(width: 17, height: 17)
                        .background(HQColor.green)
                        .clipShape(Circle())
                    Text("added")
                        .font(HQFont.mono(11, weight: .semibold))
                        .foregroundColor(HQColor.green)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("already a contact")
            case .invited:
                Text("invited")
                    .font(HQFont.mono(11, weight: .semibold))
                    .foregroundColor(HQColor.warning)
            case .awaitingYou:
                Text("wants to connect")
                    .font(HQFont.mono(11, weight: .semibold))
                    .foregroundColor(HQColor.purpleLight)
            case .you:
                Text("you")
                    .font(HQFont.mono(11, weight: .semibold))
                    .foregroundColor(HQColor.textMuted)
            case .none:
                Button(action: onAdd) {
                    Image(systemName: "person.badge.plus")
                        .font(.system(size: 15))
                        .foregroundColor(HQColor.green)
                        .frame(width: 34, height: 34)
                        .background(HQColor.green.opacity(0.08))
                        .overlay(RoundedRectangle(cornerRadius: 3).stroke(HQColor.green.opacity(0.4), lineWidth: 1))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                        .frame(minWidth: 44, minHeight: 44)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("add @\(user.username)")
            }
        }
    }
}
