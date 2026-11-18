import Foundation

// Who has to update before a group can include a v6 identity.
//
// Every member of a group receives the whole roster. An app from before 4.0
// cannot parse a 64-character fingerprint, and when it meets one in a roster
// it drops that member and keeps going, with no error. From then on it refuses
// that member's messages as coming from a stranger, and never sends its own
// messages to them. Nobody is told. So a roster that includes a v6 identity is
// only allowed when every member's app can hold one.
//
// What a member's app supports is what they told us (Contact.caps). A member
// who has said nothing is counted as needing to update: that is the truth for
// an older app, and for a 4.0 app it clears up the first time they come online,
// because every 4.0 app announces its caps to its contacts.
//
// Channels need no such rule. A subscriber only ever receives the admins'
// roster, never the other subscribers, so who else is subscribed makes no
// difference to anyone. What is checked for a channel is the admin, when a v6
// identity subscribes (see ChatStore.channelAdminNeedsUpdate).

enum GroupRules {

    struct Member {
        let fingerprint: Fingerprint
        let caps: [String]?
        let label: String
    }

    /// The members who must update before `roster` can be a group. Empty when
    /// the roster is fine as it is, which is always the case when nobody in it
    /// has a v6 identity.
    static func needingUpdate(_ roster: [Member]) -> [Member] {
        guard roster.contains(where: { $0.fingerprint.isV6 }) else { return [] }
        return roster.filter { !PairingCaps.peerSupportsV6($0.fingerprint, caps: $0.caps) }
    }
}
