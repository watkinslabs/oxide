// NETLINK_GENERIC ABI numbers. Constants only — dispatch, permission checks,
// and registry state live in the sibling implementation modules.

extern crate alloc;

/// Maximum family / multicast-group name length INCLUDING the NUL.
pub const GENL_NAMSIZ: usize = 16;

/// Lowest family id genetlink may hand out (== `NLMSG_MIN_TYPE`).
pub const GENL_MIN_ID: u16 = 0x10;
/// Highest family id genetlink may hand out.
pub const GENL_MAX_ID: u16 = 1023;

/// Statically reserved family ids. Three families historically used their
/// family id as their multicast-group id, so both spaces reserve the same
/// numbers for them.
pub const GENL_ID_CTRL:      u16 = GENL_MIN_ID;
pub const GENL_ID_VFS_DQUOT: u16 = GENL_MIN_ID + 1;
pub const GENL_ID_PMCRAID:   u16 = GENL_MIN_ID + 2;
/// First dynamically allocatable family id.
pub const GENL_START_ALLOC:  u16 = GENL_MIN_ID + 3;

/// Multicast-group id reserved for the `NET_DM` family.
pub const GENL_GRP_ID_NET_DM: u32 = 1;
/// First dynamically allocatable multicast-group id. Ids 0 and
/// `GENL_GRP_ID_NET_DM` plus the three static family ids are pre-reserved.
pub const GENL_GRP_ID_MIN: u32 = 2;

/// `genl_ops.flags` bits.
pub mod op_flags {
    /// Command requires `CAP_NET_ADMIN` in the initial user namespace.
    pub const GENL_ADMIN_PERM:     u32 = 0x01;
    /// Command has a `doit` handler.
    pub const GENL_CMD_CAP_DO:     u32 = 0x02;
    /// Command has a `dumpit` handler.
    pub const GENL_CMD_CAP_DUMP:   u32 = 0x04;
    /// Command carries an attribute validation policy.
    pub const GENL_CMD_CAP_HASPOL: u32 = 0x08;
    /// Command requires `CAP_NET_ADMIN` in the socket's user namespace.
    pub const GENL_UNS_ADMIN_PERM: u32 = 0x10;
}

/// `nlctrl` family name — the bootstrap every genetlink client resolves first.
pub const CTRL_FAMILY_NAME: &str = "nlctrl";
/// `nlctrl` protocol version.
pub const CTRL_VERSION: u8 = 2;
/// `nlctrl`'s single multicast group.
pub const CTRL_GROUP_NOTIFY: &str = "notify";
/// First `nlctrl` command validated against the strict header rules.
pub const CTRL_RESV_START_OP: u8 = ctrl_cmd::CTRL_CMD_GETPOLICY + 1;

pub mod ctrl_cmd {
    pub const CTRL_CMD_UNSPEC:        u8 = 0;
    pub const CTRL_CMD_NEWFAMILY:     u8 = 1;
    pub const CTRL_CMD_DELFAMILY:     u8 = 2;
    pub const CTRL_CMD_GETFAMILY:     u8 = 3;
    pub const CTRL_CMD_NEWOPS:        u8 = 4;
    pub const CTRL_CMD_DELOPS:        u8 = 5;
    pub const CTRL_CMD_GETOPS:        u8 = 6;
    pub const CTRL_CMD_NEWMCAST_GRP:  u8 = 7;
    pub const CTRL_CMD_DELMCAST_GRP:  u8 = 8;
    pub const CTRL_CMD_GETMCAST_GRP:  u8 = 9;
    pub const CTRL_CMD_GETPOLICY:     u8 = 10;
    pub const CTRL_CMD_MAX:           u8 = CTRL_CMD_GETPOLICY;
}

pub mod ctrl_attr {
    pub const CTRL_ATTR_UNSPEC:       u16 = 0;
    pub const CTRL_ATTR_FAMILY_ID:    u16 = 1;
    pub const CTRL_ATTR_FAMILY_NAME:  u16 = 2;
    pub const CTRL_ATTR_VERSION:      u16 = 3;
    pub const CTRL_ATTR_HDRSIZE:      u16 = 4;
    pub const CTRL_ATTR_MAXATTR:      u16 = 5;
    pub const CTRL_ATTR_OPS:          u16 = 6;
    pub const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
    pub const CTRL_ATTR_POLICY:       u16 = 8;
    pub const CTRL_ATTR_OP_POLICY:    u16 = 9;
    pub const CTRL_ATTR_OP:           u16 = 10;
    pub const CTRL_ATTR_MAX:          u16 = CTRL_ATTR_OP;
}

pub mod ctrl_attr_op {
    pub const CTRL_ATTR_OP_UNSPEC: u16 = 0;
    pub const CTRL_ATTR_OP_ID:     u16 = 1;
    pub const CTRL_ATTR_OP_FLAGS:  u16 = 2;
}

pub mod ctrl_attr_mcast_grp {
    pub const CTRL_ATTR_MCAST_GRP_UNSPEC: u16 = 0;
    pub const CTRL_ATTR_MCAST_GRP_NAME:   u16 = 1;
    pub const CTRL_ATTR_MCAST_GRP_ID:     u16 = 2;
}

/// `CTRL_ATTR_POLICY` sub-attributes describing one attribute's validation.
pub mod policy_attr {
    pub const NL_POLICY_TYPE_ATTR_UNSPEC:      u16 = 0;
    pub const NL_POLICY_TYPE_ATTR_TYPE:        u16 = 1;
    pub const NL_POLICY_TYPE_ATTR_MIN_LENGTH:  u16 = 6;
    pub const NL_POLICY_TYPE_ATTR_MAX_LENGTH:  u16 = 7;
}

/// `NL_ATTR_TYPE_*` wire kinds reported by a policy dump.
pub mod policy_type {
    pub const NL_ATTR_TYPE_U16:        u32 = 4;
    pub const NL_ATTR_TYPE_U32:        u32 = 5;
    pub const NL_ATTR_TYPE_BINARY:     u32 = 13;
    pub const NL_ATTR_TYPE_NUL_STRING: u32 = 11;
}

/// `CTRL_ATTR_OP_POLICY` sub-attributes: which policy index a command's
/// `doit`/`dumpit` validates against.
pub mod op_policy_attr {
    pub const CTRL_ATTR_POLICY_DO:   u16 = 1;
    pub const CTRL_ATTR_POLICY_DUMP: u16 = 2;
}

/// 4-byte `genlmsghdr` that prefixes every NETLINK_GENERIC payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Genlmsghdr {
    pub cmd:      u8,
    pub version:  u8,
    pub reserved: u16,
}

impl Genlmsghdr {
    /// `GENL_HDRLEN` — already `NLMSG_ALIGN`ed at 4 bytes.
    pub const SIZE: usize = 4;

    /// Decode a `genlmsghdr` from the front of a payload. # C: O(1)
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE { return None; }
        Some(Self {
            cmd:      buf[0],
            version:  buf[1],
            reserved: u16::from_ne_bytes([buf[2], buf[3]]),
        })
    }

    /// Encode a `genlmsghdr`. # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.cmd;
        buf[1] = self.version;
        buf[2..4].copy_from_slice(&self.reserved.to_ne_bytes());
    }
}
