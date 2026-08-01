// The `VFS_DQUOT` family: quota-limit warnings broadcast to `quota_nld`.
//
// Quota accounting raises a warning class the moment an id crosses a soft or
// hard limit (or drops back under one). The VFS owns generating them; this is
// the transport, registered as the family's only producer and installed as the
// VFS warning hook so a generated warning actually leaves the kernel.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::family::{self, GenlFamilySpec};
use super::mcast::{self, GenlMcastError};
use super::message;
use super::{attr, uapi};

/// Family name userspace resolves through `nlctrl`.
pub const QUOTA_FAMILY_NAME: &str = "VFS_DQUOT";
/// The family's single multicast group.
pub const QUOTA_GROUP_EVENTS: &str = "events";
/// Group INDEX of `events` inside the family's group table.
pub const QUOTA_EVENTS_INDEX: usize = 0;
/// Family protocol version.
pub const QUOTA_FAMILY_VERSION: u8 = 1;

/// `QUOTA_NL_C_*` commands.
pub mod quota_nl_cmd {
    pub const QUOTA_NL_C_UNSPEC:  u8 = 0;
    pub const QUOTA_NL_C_WARNING: u8 = 1;
    pub const QUOTA_NL_C_MAX:     u8 = QUOTA_NL_C_WARNING;
}

/// `QUOTA_NL_A_*` attributes of a warning.
pub mod quota_nl_attr {
    pub const QUOTA_NL_A_UNSPEC:    u16 = 0;
    pub const QUOTA_NL_A_QTYPE:     u16 = 1;
    pub const QUOTA_NL_A_EXCESS_ID: u16 = 2;
    pub const QUOTA_NL_A_WARNING:   u16 = 3;
    pub const QUOTA_NL_A_DEV_MAJOR: u16 = 4;
    pub const QUOTA_NL_A_DEV_MINOR: u16 = 5;
    pub const QUOTA_NL_A_CAUSED_ID: u16 = 6;
    pub const QUOTA_NL_A_PAD:       u16 = 7;
    pub const QUOTA_NL_A_MAX:       u16 = QUOTA_NL_A_PAD;
}

/// Per-warning sequence counter carried in `nlmsg_seq`.
static WARNING_SEQ: AtomicU32 = AtomicU32::new(0);

/// Register `VFS_DQUOT` and install it as the VFS warning transport.
/// # C: O(N families)
pub fn init() -> Result<u16, family::GenlRegError> {
    let id = family::register_family(GenlFamilySpec {
        name:    QUOTA_FAMILY_NAME,
        version: QUOTA_FAMILY_VERSION,
        hdrsize: 0,
        maxattr: quota_nl_attr::QUOTA_NL_A_MAX,
        ops:     Vec::new(),
        mcgrps:  alloc::vec![QUOTA_GROUP_EVENTS],
        netnsok: false,
        resv_start_op: quota_nl_cmd::QUOTA_NL_C_UNSPEC,
    })?;
    vfs::set_quota_warn_hook(send_warning);
    Ok(id)
}

/// Build one `QUOTA_NL_C_WARNING` message. Both id attributes are 64-bit and
/// therefore carry the padding attribute netlink needs to keep their payload
/// 8-byte aligned. # C: O(1)
pub fn build_warning(seq: u32, family_id: u16, warning: vfs::QuotaWarning) -> Vec<u8> {
    let mut out = message::start(0, seq, family_id, QUOTA_FAMILY_VERSION, 0,
        quota_nl_cmd::QUOTA_NL_C_WARNING);
    attr::put_u32(&mut out, quota_nl_attr::QUOTA_NL_A_QTYPE, warning.qid.kind.slot() as u32);
    attr::put_u64_64bit(&mut out, quota_nl_attr::QUOTA_NL_A_EXCESS_ID,
        warning.qid.id as u64, quota_nl_attr::QUOTA_NL_A_PAD);
    attr::put_u32(&mut out, quota_nl_attr::QUOTA_NL_A_WARNING, warning.warn_type.as_u32());
    attr::put_u32(&mut out, quota_nl_attr::QUOTA_NL_A_DEV_MAJOR, vfs::kdev_major(warning.dev));
    attr::put_u32(&mut out, quota_nl_attr::QUOTA_NL_A_DEV_MINOR, vfs::kdev_minor(warning.dev));
    attr::put_u64_64bit(&mut out, quota_nl_attr::QUOTA_NL_A_CAUSED_ID,
        warning.caused_by_uid as u64, quota_nl_attr::QUOTA_NL_A_PAD);
    message::end(&mut out, 0);
    out
}

/// `quota_send_warning`: broadcast one warning on the family's `events` group.
/// Nobody listening is not an error — quota accounting proceeds either way.
/// # C: O(N_listeners)
pub fn send_warning(warning: vfs::QuotaWarning) {
    let _ = multicast_warning(warning);
}

/// Broadcast one warning, reporting the delivery outcome. # C: O(N_listeners)
pub fn multicast_warning(warning: vfs::QuotaWarning) -> Result<usize, GenlMcastError> {
    let Some(fam) = family::find_by_name(QUOTA_FAMILY_NAME) else {
        return Err(GenlMcastError::Einval);
    };
    let seq = WARNING_SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    let body = build_warning(seq, fam.id, warning);
    mcast::genlmsg_multicast(&fam, QUOTA_EVENTS_INDEX, &body, 0)
}

/// Decode the warning attributes of a `QUOTA_NL_C_WARNING` message body.
/// # C: O(N attrs)
pub fn parse_warning(body: &[u8]) -> Option<ParsedWarning> {
    let hdr = crate::Nlmsghdr::parse(body)?;
    let gh = uapi::Genlmsghdr::parse(&body[crate::Nlmsghdr::SIZE..])?;
    let attrs = &body[crate::Nlmsghdr::SIZE + uapi::Genlmsghdr::SIZE..hdr.nlmsg_len as usize];
    let u32_at = |ty: u16| attr::find(attrs, ty)
        .and_then(|a| a.payload.get(..4).map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]])));
    let u64_at = |ty: u16| attr::find(attrs, ty).and_then(|a| a.payload.get(..8)
        .map(|b| u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])));
    Some(ParsedWarning {
        family_id: hdr.nlmsg_type,
        cmd:       gh.cmd,
        version:   gh.version,
        qtype:     u32_at(quota_nl_attr::QUOTA_NL_A_QTYPE)?,
        excess_id: u64_at(quota_nl_attr::QUOTA_NL_A_EXCESS_ID)?,
        warning:   u32_at(quota_nl_attr::QUOTA_NL_A_WARNING)?,
        dev_major: u32_at(quota_nl_attr::QUOTA_NL_A_DEV_MAJOR)?,
        dev_minor: u32_at(quota_nl_attr::QUOTA_NL_A_DEV_MINOR)?,
        caused_id: u64_at(quota_nl_attr::QUOTA_NL_A_CAUSED_ID)?,
    })
}

/// Decoded `QUOTA_NL_C_WARNING` payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedWarning {
    pub family_id: u16,
    pub cmd:       u8,
    pub version:   u8,
    pub qtype:     u32,
    pub excess_id: u64,
    pub warning:   u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub caused_id: u64,
}
