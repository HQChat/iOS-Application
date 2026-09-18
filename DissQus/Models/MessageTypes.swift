//
//  MessageTypes.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import Foundation

/// What is left of the old `/ws` protocol types after the MQTT cutover: one
/// directory row.
///
/// Everything else that used to live here — `MessageTypeToSend`,
/// `MessageTypeToReceive`, `OutgoingMessage`, `IncomingMessage` — described a
/// single socket carrying forty-odd message kinds. There is no such socket now:
/// the control plane is REST (`APIClient`), and the only thing clients send each
/// other is a `ConversationFrame`, which has two cases and never touches the
/// server in readable form.

/// A user as returned by the directory lookup (exact username → client id).
///
/// `id`, not `pk`: the directory deals in `sha256(lowercase-hex(publicKey))`,
/// which is what every other layer names a person by. The key itself is fetched
/// once the person becomes a contact — and verified against this id before it is
/// pinned, which is what makes the lookup safe to trust at all.
struct UserListItem: Codable {
    let username: String
    let id: String
}
