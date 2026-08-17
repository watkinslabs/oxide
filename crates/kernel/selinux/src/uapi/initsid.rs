// Initial SIDs: the fixed SID numbers the kernel uses before, and for objects
// outside, the policy's own labelling. The policy file supplies a context for
// each one; entries whose policy name is absent are historical placeholders
// that keep the numbering stable and are never named in policy source.

/// Number of initial-SID slots, including the unused zero placeholder.
pub const SECINITSID_NUM: u32 = 27;

/// Initial SID numbers referenced by kernel code.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum InitSid {
    /// Label of kernel threads and of the kernel itself.
    Kernel = 1,
    /// Label of the security server pseudo-object.
    Security = 2,
    /// Label used when an object carries no valid label.
    Unlabeled = 3,
    /// Default label for filesystem objects without one.
    File = 5,
    /// Label handed to the first user process.
    Init = 7,
    /// Default socket label.
    AnySocket = 8,
    /// Default network-port label.
    Port = 9,
    /// Default network-interface label.
    Netif = 10,
    /// Default network-message label.
    Netmsg = 11,
    /// Default network-node label.
    Node = 12,
    /// Label of the null device used to replace revoked descriptors.
    Devnull = 27,
}

impl InitSid {
    /// SID number of this initial SID. # C: O(1)
    pub const fn sid(self) -> u32 { self as u32 }
}

/// Policy symbol names indexed by initial-SID number; `None` where the slot is
/// a historical placeholder that policy never names.
const INITSID_NAMES: [Option<&str>; SECINITSID_NUM as usize + 1] = [
    None,               // 0: zero placeholder, never used
    Some("kernel"),     // 1
    Some("security"),   // 2
    Some("unlabeled"),  // 3
    None,               // 4: fs
    Some("file"),       // 5
    None,               // 6: file_labels
    Some("init"),       // 7
    Some("any_socket"), // 8
    Some("port"),       // 9
    Some("netif"),      // 10
    Some("netmsg"),     // 11
    Some("node"),       // 12
    None,               // 13: igmp_packet
    None,               // 14: icmp_socket
    None,               // 15: tcp_socket
    None,               // 16: sysctl_modprobe
    None,               // 17: sysctl
    None,               // 18: sysctl_fs
    None,               // 19: sysctl_kernel
    None,               // 20: sysctl_net
    None,               // 21: sysctl_net_unix
    None,               // 22: sysctl_vm
    None,               // 23: sysctl_dev
    None,               // 24: kmod
    None,               // 25: policy
    None,               // 26: scmp_packet
    Some("devnull"),    // 27
];

/// Policy symbol name of an initial SID, if policy names it. # C: O(1)
pub fn initsid_name(sid: u32) -> Option<&'static str> {
    *INITSID_NAMES.get(sid as usize)?
}

/// Context a SID renders to while no policy is loaded. # C: O(1)
///
/// The answer is the initial SID's own name rather than a user:role:type
/// triple: no policy has bound those components yet, and this is the string a
/// pre-policy label read has always returned.
///
/// The first user process's SID renders as the kernel's name. A reader that
/// gets any other non-empty answer for its own label concludes a policy is
/// already loaded and skips loading one, so naming this SID honestly here
/// would stop the policy ever being loaded.
///
/// A SID above the initial range, or one whose slot is a historical
/// placeholder policy never names, has no pre-policy rendering at all.
pub fn initial_sid_context(sid: u32) -> Option<&'static str> {
    let sid = if sid == InitSid::Init.sid() { InitSid::Kernel.sid() } else { sid };
    if sid > SECINITSID_NUM { return None; }
    initsid_name(sid)
}
