// Per-datagram sender credentials a NETLINK message carries, and the rule
// deciding whether a receive reports them as `SCM_CREDENTIALS`.
//
// Ungated on purpose: this is the decision logic the recvmsg shim consults,
// so it must be reachable by hosted `cargo test` (`docs/53`).

use net::sock_opts::SenderCreds;

/// Credentials one queued datagram carries with it, the sender identity a
/// receive reports when the receiving socket asked for credentials. A message
/// the kernel originated carries the all-zero set: pid 0 names the kernel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetlinkCreds {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl NetlinkCreds {
    /// The credential set a kernel-originated datagram carries. # C: O(1)
    pub const KERNEL: Self = Self { pid: 0, uid: 0, gid: 0 };

    /// Adopt a sending task's snapshot for a userspace-originated datagram. # C: O(1)
    pub fn from_sender(creds: SenderCreds) -> Self {
        Self { pid: creds.pid, uid: creds.uid, gid: creds.gid }
    }

    /// The `(pid, uid, gid)` triple a `SCM_CREDENTIALS` payload carries. # C: O(1)
    pub fn as_triple(&self) -> (u32, u32, u32) { (self.pid, self.uid, self.gid) }
}

/// The sending task's set, stamped onto a datagram as it is committed. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn current_sender() -> NetlinkCreds { NetlinkCreds::from_sender(SenderCreds::current()) }

/// Hosted builds have no running task to stamp from. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn current_sender() -> NetlinkCreds { NetlinkCreds::KERNEL }

/// Credentials a receive reports for one datagram. A socket that did not set
/// `SO_PASSCRED` is told nothing, whatever the netlink protocol and whoever
/// sent the message; a socket that did is told the sender's set, all-zero for
/// everything the kernel produced.
/// # C: O(1)
pub fn reported(passcred: bool, carried: NetlinkCreds) -> Option<(u32, u32, u32)> {
    if passcred { Some(carried.as_triple()) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_that_did_not_ask_is_told_nothing() {
        assert_eq!(reported(false, NetlinkCreds::KERNEL), None);
        assert_eq!(reported(false, NetlinkCreds { pid: 7, uid: 1000, gid: 1000 }), None);
    }

    #[test]
    fn a_kernel_datagram_reports_the_all_zero_set() {
        assert_eq!(reported(true, NetlinkCreds::KERNEL), Some((0, 0, 0)));
    }

    #[test]
    fn a_userspace_datagram_reports_its_senders_set() {
        let carried = NetlinkCreds::from_sender(SenderCreds { pid: 41, uid: 1000, gid: 1001 });
        assert_eq!(reported(true, carried), Some((41, 1000, 1001)));
    }

    #[test]
    fn the_reporting_rule_does_not_depend_on_the_protocol() {
        // The uevent socket is not special: one rule covers every protocol,
        // so a NETLINK_ROUTE reader that asked is answered the same way a
        // NETLINK_KOBJECT_UEVENT reader is.
        for carried in [NetlinkCreds::KERNEL, NetlinkCreds { pid: 3, uid: 4, gid: 5 }] {
            assert_eq!(reported(true, carried), Some(carried.as_triple()));
            assert_eq!(reported(false, carried), None);
        }
    }
}
