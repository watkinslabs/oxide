use core::sync::atomic::{AtomicU32, Ordering};

/// `AF_NETLINK` numeric. Used by sys_socket dispatch.
pub use net::socket_args::AF_NETLINK_WIRE as AF_NETLINK;

/// Linux's unconnected NETLINK destination port-id.
pub const NETLINK_UNCONNECTED_PORT_ID: u32 = 0;
/// Linux's unconnected NETLINK destination multicast-group mask.
pub const NETLINK_UNCONNECTED_GROUPS: u32 = 0;

/// `NETLINK_*` protocol family ids per `linux/netlink.h`.
pub mod proto {
    pub const NETLINK_ROUTE:          u16 =  0;
    pub const NETLINK_USERSOCK:       u16 =  2;
    pub const NETLINK_FIREWALL:       u16 =  3;
    pub const NETLINK_SOCK_DIAG:      u16 =  4;
    pub const NETLINK_NFLOG:          u16 =  5;
    pub const NETLINK_XFRM:           u16 =  6;
    pub const NETLINK_SELINUX:        u16 =  7;
    pub const NETLINK_ISCSI:          u16 =  8;
    pub const NETLINK_AUDIT:          u16 =  9;
    pub const NETLINK_FIB_LOOKUP:     u16 = 10;
    pub const NETLINK_CONNECTOR:      u16 = 11;
    pub const NETLINK_NETFILTER:      u16 = 12;
    pub const NETLINK_IP6_FW:         u16 = 13;
    pub const NETLINK_DNRTMSG:        u16 = 14;
    pub const NETLINK_KOBJECT_UEVENT: u16 = 15;
    pub const NETLINK_GENERIC:        u16 = 16;
    pub const NETLINK_SCSITRANSPORT:  u16 = 18;
    pub const NETLINK_ECRYPTFS:       u16 = 19;
    pub const NETLINK_RDMA:           u16 = 20;
    pub const NETLINK_CRYPTO:         u16 = 21;
}

/// `struct nlmsghdr` flags per `linux/netlink.h`.
pub mod flags {
    pub const NLM_F_REQUEST:   u16 = 0x0001;
    pub const NLM_F_MULTI:     u16 = 0x0002;
    pub const NLM_F_ACK:       u16 = 0x0004;
    pub const NLM_F_ECHO:      u16 = 0x0008;
    pub const NLM_F_DUMP_INTR: u16 = 0x0010;
    pub const NLM_F_ROOT:      u16 = 0x0100;
    pub const NLM_F_MATCH:     u16 = 0x0200;
    pub const NLM_F_ATOMIC:    u16 = 0x0400;
    pub const NLM_F_DUMP:      u16 = NLM_F_ROOT | NLM_F_MATCH;
    pub const NLM_F_REPLACE:   u16 = 0x0100;
    pub const NLM_F_EXCL:      u16 = 0x0200;
    pub const NLM_F_CREATE:    u16 = 0x0400;
    pub const NLM_F_APPEND:    u16 = 0x0800;
}

/// Reserved `nlmsg_type` values. Per-protocol types start at 16.
pub mod msg {
    pub const NLMSG_NOOP:    u16 = 1;
    pub const NLMSG_ERROR:   u16 = 2;
    pub const NLMSG_DONE:    u16 = 3;
    pub const NLMSG_OVERRUN: u16 = 4;
}

/// 16-byte `struct nlmsghdr` (host-endian; Linux netlink runs on
/// the local byte order).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Nlmsghdr {
    pub nlmsg_len:   u32,
    pub nlmsg_type:  u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq:   u32,
    pub nlmsg_pid:   u32,
}

impl Nlmsghdr {
    pub const SIZE: usize = 16;

    /// Decode the leading header out of a buffer. Caller validates
    /// `buf.len() >= Nlmsghdr::SIZE` first.
    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE { return None; }
        let nlmsg_len = u32::from_ne_bytes(buf[0..4].try_into().ok()?);
        let nlmsg_type = u16::from_ne_bytes(buf[4..6].try_into().ok()?);
        let nlmsg_flags = u16::from_ne_bytes(buf[6..8].try_into().ok()?);
        let nlmsg_seq = u32::from_ne_bytes(buf[8..12].try_into().ok()?);
        let nlmsg_pid = u32::from_ne_bytes(buf[12..16].try_into().ok()?);
        Some(Self { nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid })
    }

    /// Serialize into the leading bytes of `buf`.
    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.nlmsg_len.to_ne_bytes());
        buf[4..6].copy_from_slice(&self.nlmsg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&self.nlmsg_flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.nlmsg_seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.nlmsg_pid.to_ne_bytes());
    }

    /// Build a NLMSG_DONE terminator with the given seq/pid.
    /// # C: O(1)
    pub fn done(seq: u32, pid: u32) -> Self {
        Self {
            nlmsg_len:   Self::SIZE as u32,
            nlmsg_type:  msg::NLMSG_DONE,
            nlmsg_flags: 0,
            nlmsg_seq:   seq,
            nlmsg_pid:   pid,
        }
    }
}

/// Netlink message round to 4 bytes (NLMSG_ALIGNTO).
/// # C: O(1)
#[inline]
pub fn nlmsg_align(len: usize) -> usize { (len + 3) & !3 }

static NEXT_KERNEL_PID: AtomicU32 = AtomicU32::new(1);

/// Allocate a fresh port-id for a newly-opened socket. PID 0 is
/// reserved for kernel-originated messages.
/// # C: O(1)
pub fn alloc_port_id() -> u32 {
    NEXT_KERNEL_PID.fetch_add(1, Ordering::AcqRel)
}
