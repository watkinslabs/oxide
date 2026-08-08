// Who decides whether an IPv6 packet carries a generated flow label.
//
// Two questions share one policy and must never be answered separately: what
// `IPV6_AUTOFLOWLABEL` reads back, and whether the transmit path generates a
// label. The socket bit alone answers neither — a socket that never named a
// policy inherits the namespace's, and the namespace can also forbid
// generation outright or force it on a socket that opted out.

/// `net.ipv6.auto_flowlabels` policies.
pub const OFF: i64 = 0;
pub const OPTOUT: i64 = 1;
pub const OPTIN: i64 = 2;
pub const FORCED: i64 = 3;
/// The compiled namespace default: sockets are opted IN unless they say
/// otherwise, which is why an untouched socket reads back `1`.
pub const DEFAULT_POLICY: i64 = OPTOUT;
pub const MAX_POLICY: i64 = FORCED;

/// The namespace's answer for a socket that named no policy of its own.
/// # C: O(1)
pub fn namespace_default(policy: i64) -> bool {
    matches!(policy, OPTOUT | FORCED)
}

/// What the socket's own policy is — what `IPV6_AUTOFLOWLABEL` reads back.
/// A socket that never wrote the option inherits the namespace's answer.
/// # C: O(1)
pub fn socket_policy(named: bool, socket_bit: bool, policy: i64) -> bool {
    if named { socket_bit } else { namespace_default(policy) }
}

/// Whether one transmitted packet carries a generated label. The namespace has
/// the last word in both directions: `OFF` suppresses generation for every
/// socket, and `FORCED` generates one even for a socket that opted out.
/// # C: O(1)
pub fn generates(named: bool, socket_bit: bool, policy: i64) -> bool {
    if policy == OFF { return false; }
    if policy == FORCED { return true; }
    socket_policy(named, socket_bit, policy)
}

#[cfg(test)]
#[path = "autolabel/tests.rs"]
mod tests;
