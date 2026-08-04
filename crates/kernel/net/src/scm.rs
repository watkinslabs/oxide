// SOL_SOCKET-level receive ancillary state and decisions, shared by every
// family that may carry them. One owner, mirroring the single `scm_recv`
// every family's recvmsg calls, so AF_UNIX and AF_NETLINK cannot drift.
//
// Ungated: the decisions must run under hosted `cargo test` (`docs/53`).

use core::sync::atomic::{AtomicI32, Ordering};

use crate::sock_opts::SenderCreds;

/// Families whose sockets may carry receive credentials. Setting or reading
/// `SO_PASSCRED`/`SO_PASSSEC` on anything else is EOPNOTSUPP, not a silently
/// stored flag. # C: O(1)
pub fn may_scm_recv(family: u16) -> bool {
    let family = family as u32;
    family == crate::socket_args::AF_UNIX
        || family == crate::socket_args::AF_NETLINK
        || family == AF_BLUETOOTH
}

/// `AF_BLUETOOTH` — named here because the credential gate is the only thing
/// in this crate that needs the number.
pub const AF_BLUETOOTH: u32 = 31;

/// `sk_scm_credentials`: whether receives on this socket report the sender's
/// credentials. One storage type for every family that has the flag.
#[derive(Debug, Default)]
pub struct ScmCredentials(AtomicI32);

impl ScmCredentials {
    /// A socket that has not asked for credentials. # C: O(1)
    pub const fn new() -> Self { Self(AtomicI32::new(0)) }

    /// Whether receives report credentials. # C: O(1)
    pub fn on(&self) -> bool { self.0.load(Ordering::Acquire) != 0 }

    /// Apply a `SO_PASSCRED` write. # C: O(1)
    pub fn set(&self, on: bool) { self.0.store(i32::from(on), Ordering::Release); }

    /// The `SO_PASSCRED` value a read reports. # C: O(1)
    pub fn value(&self) -> i32 { self.0.load(Ordering::Acquire) }
}

/// `sk_scm_security`: whether receives report the sender label carried with a
/// record.  Kept beside the shared SCM decision types for socket families
/// that have not yet been folded into `InetSocket`'s generic option storage.
#[derive(Debug, Default)]
pub struct ScmSecurity(AtomicI32);

impl ScmSecurity {
    /// A socket that has not asked for security labels. # C: O(1)
    pub const fn new() -> Self { Self(AtomicI32::new(0)) }
    /// Whether receives report their carried security label. # C: O(1)
    pub fn on(&self) -> bool { self.0.load(Ordering::Acquire) != 0 }
    /// Apply a `SO_PASSSEC` write. # C: O(1)
    pub fn set(&self, on: bool) { self.0.store(i32::from(on), Ordering::Release); }
    /// The `SO_PASSSEC` value a read reports. # C: O(1)
    pub fn value(&self) -> i32 { self.0.load(Ordering::Acquire) }
}

/// The credentials a receive reports for one message: the sender's set when
/// the RECEIVING socket asked for them, nothing otherwise. Whoever sent the
/// message and whichever protocol carried it are not part of the decision.
/// # C: O(1)
pub fn recv(passcred: bool, carried: SenderCreds) -> Option<(u32, u32, u32)> {
    if passcred { Some((carried.pid, carried.uid, carried.gid)) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket_args::{AF_INET, AF_INET6, AF_NETLINK, AF_UNIX};

    #[test]
    fn only_the_credential_carrying_families_may_ask() {
        for family in [AF_UNIX, AF_NETLINK, AF_BLUETOOTH] {
            assert!(may_scm_recv(family as u16), "family {family}");
        }
        for family in [AF_INET, AF_INET6] {
            assert!(!may_scm_recv(family as u16), "family {family}");
        }
    }

    #[test]
    fn a_socket_that_did_not_ask_is_told_nothing() {
        let creds = SenderCreds { pid: 7, uid: 1000, gid: 1000 };
        assert_eq!(recv(false, creds), None);
        assert_eq!(recv(false, SenderCreds::default()), None);
    }

    #[test]
    fn a_socket_that_asked_is_told_the_senders_set() {
        assert_eq!(recv(true, SenderCreds { pid: 41, uid: 1000, gid: 1001 }),
            Some((41, 1000, 1001)));
    }

    // A message the kernel produced carries the all-zero set: pid 0 names the
    // kernel, and a reader that asked is told that rather than nothing.
    #[test]
    fn a_kernel_message_reports_the_all_zero_set() {
        assert_eq!(recv(true, SenderCreds::default()), Some((0, 0, 0)));
    }

    #[test]
    fn the_flag_starts_off_and_round_trips() {
        let f = ScmCredentials::new();
        assert!(!f.on());
        assert_eq!(f.value(), 0);
        f.set(true);
        assert!(f.on());
        assert_eq!(f.value(), 1);
        f.set(false);
        assert!(!f.on());
    }

    #[test]
    fn security_flag_starts_off_and_round_trips() {
        let f = ScmSecurity::new();
        assert!(!f.on());
        assert_eq!(f.value(), 0);
        f.set(true);
        assert!(f.on());
        assert_eq!(f.value(), 1);
        f.set(false);
        assert!(!f.on());
    }
}
