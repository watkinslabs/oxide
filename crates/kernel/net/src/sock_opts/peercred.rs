/// `SO_PEERCRED` value encoding — the one owner of what a socket answers when
/// it has, and when it has NOT, pinned a peer identity.
///
/// Linux builds the reply from `sk_peer_pid` / `sk_peer_cred`, both NULL until
/// a connect/accept/socketpair pins them. A NULL pid renders as 0 and a NULL
/// cred leaves uid and gid at the `(uid_t)-1` the reply was initialised with.
/// The caller's own credentials are never consulted.
/// `struct ucred` — `{ pid_t pid; uid_t uid; gid_t gid; }`.
pub const UCRED_BYTES: usize = 12;

/// The `uid`/`gid` a socket with no pinned peer credential reports.
pub const UCRED_NO_CRED_ID: u32 = u32::MAX;
/// The `pid` a socket with no pinned peer identity reports.
pub const UCRED_NO_PID: i32 = 0;

/// Encode `struct ucred` for a socket that pinned `peer`, or for one that
/// never did (`None`). # C: O(1)
pub fn ucred_bytes(peer: Option<(i32, u32, u32)>) -> [u8; UCRED_BYTES] {
    let (pid, uid, gid) = peer
        .unwrap_or((UCRED_NO_PID, UCRED_NO_CRED_ID, UCRED_NO_CRED_ID));
    let mut value = [0u8; UCRED_BYTES];
    value[..4].copy_from_slice(&pid.to_ne_bytes());
    value[4..8].copy_from_slice(&uid.to_ne_bytes());
    value[8..].copy_from_slice(&gid.to_ne_bytes());
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(value: [u8; UCRED_BYTES]) -> (i32, u32, u32) {
        (i32::from_ne_bytes(value[..4].try_into().unwrap()),
         u32::from_ne_bytes(value[4..8].try_into().unwrap()),
         u32::from_ne_bytes(value[8..].try_into().unwrap()))
    }

    #[test]
    fn a_socket_that_never_pinned_a_peer_reports_pid_zero_and_minus_one_ids() {
        // Not the caller's own {pid,euid,egid}: an unconnected or non-AF_UNIX
        // socket has no peer to describe, so the ids stay at their initialised
        // `(uid_t)-1` and the pid renders a NULL identity as 0.
        assert_eq!(decode(ucred_bytes(None)), (0, u32::MAX, u32::MAX));
    }

    #[test]
    fn a_pinned_peer_is_reported_verbatim() {
        assert_eq!(decode(ucred_bytes(Some((4242, 1000, 1001)))), (4242, 1000, 1001));
    }

    #[test]
    fn root_peer_credentials_are_not_confused_with_the_no_peer_answer() {
        assert_ne!(ucred_bytes(Some((1, 0, 0))), ucred_bytes(None));
    }
}
