// NETLINK_GENERIC (genetlink) per Linux `linux/genetlink.h`. The
// CTRL family (id=0x10, name="nlctrl") is the bootstrap — clients
// query family ids by name via CTRL_CMD_GETFAMILY, then send
// per-family messages directly with `nlmsghdr.nlmsg_type = family_id`.
//
// Wire format inside the nlmsghdr payload:
//   genlmsghdr { u8 cmd; u8 version; u16 reserved }  (4 bytes)
//   nlattr stream
//
// F94 ships the scaffold + CTRL.GETFAMILY. Per-family handlers
// (e.g. nl80211 / ethtool / nfnetlink-compat) register via
// `register_family` and land in follow-up PRs.

extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as SockLockClass};

use crate::{flags, msg, nlmsg_align, Nlmsghdr};

/// 4-byte genlmsghdr.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Genlmsghdr {
    pub cmd:      u8,
    pub version:  u8,
    pub reserved: u16,
}

impl Genlmsghdr {
    pub const SIZE: usize = 4;

    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE { return None; }
        Some(Self {
            cmd:      buf[0],
            version:  buf[1],
            reserved: u16::from_ne_bytes([buf[2], buf[3]]),
        })
    }
    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.cmd;
        buf[1] = self.version;
        buf[2..4].copy_from_slice(&self.reserved.to_ne_bytes());
    }
}

// ---- CTRL family --------------------------------------------------------

/// CTRL family id (the bootstrap family every genetlink socket
/// knows about by default). Linux defines this as
/// `GENL_ID_CTRL = NLMSG_MIN_TYPE = 0x10`.
pub const CTRL_FAMILY_ID:   u16 = 0x10;
pub const CTRL_FAMILY_NAME: &str = "nlctrl";

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
}

pub mod ctrl_attr {
    pub const CTRL_ATTR_UNSPEC:        u16 = 0;
    pub const CTRL_ATTR_FAMILY_ID:     u16 = 1;
    pub const CTRL_ATTR_FAMILY_NAME:   u16 = 2;
    pub const CTRL_ATTR_VERSION:       u16 = 3;
    pub const CTRL_ATTR_HDRSIZE:       u16 = 4;
    pub const CTRL_ATTR_MAXATTR:       u16 = 5;
    pub const CTRL_ATTR_OPS:           u16 = 6;
    pub const CTRL_ATTR_MCAST_GROUPS:  u16 = 7;
}

// ---- Family registry ----------------------------------------------------

/// One genetlink family entry. `id` is dynamically assigned at
/// register time, starting at 0x11 (CTRL is 0x10).
#[derive(Clone, Debug)]
pub struct GenlFamily {
    pub id:       u16,
    pub name:     String,
    pub version:  u8,
    pub hdrsize:  u8,
    pub maxattr:  u16,
}

static FAMILY_REGISTRY: Spinlock<Vec<GenlFamily>, SockLockClass> =
    Spinlock::new(Vec::new());

/// Register a new family. Idempotent on `name`; returns its id.
/// CTRL itself is special-cased — it doesn't live in the registry.
/// # C: O(N) name scan
pub fn register_family(name: &str, version: u8, hdrsize: u8, maxattr: u16) -> u16 {
    let mut g = FAMILY_REGISTRY.lock();
    for f in g.iter() {
        if f.name == name { return f.id; }
    }
    // Next dynamic family id. Linux starts user families at
    // GENL_ID_CTRL + 1 (0x11) and counts up; we mirror that.
    let id = (g.len() as u16) + (CTRL_FAMILY_ID + 1);
    g.push(GenlFamily {
        id, name: String::from(name),
        version, hdrsize, maxattr,
    });
    id
}

/// Look up by name. # C: O(N)
pub fn lookup_family_by_name(name: &str) -> Option<GenlFamily> {
    if name == CTRL_FAMILY_NAME {
        return Some(GenlFamily {
            id: CTRL_FAMILY_ID,
            name: String::from(CTRL_FAMILY_NAME),
            version: 2, hdrsize: 0, maxattr: 0,
        });
    }
    FAMILY_REGISTRY.lock().iter().find(|f| f.name == name).cloned()
}

/// Snapshot of registered families (excluding CTRL itself, which
/// is implicit). # C: O(N)
pub fn snapshot_families() -> Vec<GenlFamily> {
    FAMILY_REGISTRY.lock().clone()
}

// ---- Attribute helpers --------------------------------------------------

fn put_nlattr(out: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let total = 4 + payload.len();
    out.extend_from_slice(&(total as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    let pad = nlmsg_align(total) - total;
    for _ in 0..pad { out.push(0); }
}

fn put_nlattr_u16(out: &mut Vec<u8>, ty: u16, v: u16) {
    put_nlattr(out, ty, &v.to_ne_bytes());
}

fn put_nlattr_u32(out: &mut Vec<u8>, ty: u16, v: u32) {
    put_nlattr(out, ty, &v.to_ne_bytes());
}

fn put_nlattr_str(out: &mut Vec<u8>, ty: u16, s: &str) {
    let mut payload: Vec<u8> = Vec::with_capacity(s.len() + 1);
    payload.extend_from_slice(s.as_bytes());
    payload.push(0);
    put_nlattr(out, ty, &payload);
}

/// Parse attrs looking for CTRL_ATTR_FAMILY_NAME (a NUL-terminated
/// string). Returns Some(name) when present.
/// # C: O(N attrs)
fn find_family_name<'a>(attrs: &'a [u8]) -> Option<&'a str> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        if nla_type == ctrl_attr::CTRL_ATTR_FAMILY_NAME {
            let payload = &attrs[off + 4..off + nla_len];
            // Trim trailing NUL.
            let end = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
            return core::str::from_utf8(&payload[..end]).ok();
        }
        off += nlmsg_align(nla_len);
    }
    None
}

/// Build a CTRL_CMD_NEWFAMILY reply describing one family. Used
/// both for GETFAMILY responses and for unsolicited multicast on
/// family registration (latter is a follow-up).
/// # C: O(1)
fn build_newfamily_reply(seq: u32, pid: u32, fam: &GenlFamily) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    // genlmsghdr
    let mut gh_buf = [0u8; Genlmsghdr::SIZE];
    Genlmsghdr {
        cmd:      ctrl_cmd::CTRL_CMD_NEWFAMILY,
        version:  2,
        reserved: 0,
    }.write_to(&mut gh_buf);
    body.extend_from_slice(&gh_buf);

    put_nlattr_str(&mut body, ctrl_attr::CTRL_ATTR_FAMILY_NAME, &fam.name);
    put_nlattr_u16(&mut body, ctrl_attr::CTRL_ATTR_FAMILY_ID, fam.id);
    put_nlattr_u32(&mut body, ctrl_attr::CTRL_ATTR_VERSION, fam.version as u32);
    put_nlattr_u32(&mut body, ctrl_attr::CTRL_ATTR_HDRSIZE, fam.hdrsize as u32);
    put_nlattr_u32(&mut body, ctrl_attr::CTRL_ATTR_MAXATTR, fam.maxattr as u32);

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type:  CTRL_FAMILY_ID,
        nlmsg_flags: 0,
        nlmsg_seq:   seq,
        nlmsg_pid:   pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// NLMSG_ERROR reply builder. errno=0 = ack.
/// # C: O(1)
fn nlmsg_ack(req: &Nlmsghdr, err: i32) -> Vec<u8> {
    let total = Nlmsghdr::SIZE + 4 + Nlmsghdr::SIZE;
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type:  msg::NLMSG_ERROR,
        nlmsg_flags: 0,
        nlmsg_seq:   req.nlmsg_seq,
        nlmsg_pid:   req.nlmsg_pid,
    };
    let mut out = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&err.to_ne_bytes());
    let mut req_buf = [0u8; Nlmsghdr::SIZE];
    req.write_to(&mut req_buf);
    out.extend_from_slice(&req_buf);
    out
}

/// Dispatch one NETLINK_GENERIC message. `full_msg` is exactly the
/// nlmsghdr-prefixed buffer for this request (already length-validated
/// by NetlinkSocket::write).
/// # C: O(1) ctrl lookup; per-family handlers add their own cost
pub fn handle(full_msg: &[u8]) -> Vec<u8> {
    let hdr = match Nlmsghdr::parse(full_msg) {
        Some(h) => h,
        None    => return Vec::new(),
    };
    let genl_off = Nlmsghdr::SIZE;
    let gh = match Genlmsghdr::parse(&full_msg[genl_off..]) {
        Some(g) => g,
        None    => return nlmsg_ack(&hdr, -22),
    };
    if hdr.nlmsg_type == CTRL_FAMILY_ID {
        return handle_ctrl(&hdr, &gh, &full_msg[genl_off + Genlmsghdr::SIZE..]);
    }
    // Per-family registry: ack-zero for now. Specific families
    // (nl80211, ethtool, …) will register in their own modules and
    // expose a handler the kernel net path can call. v1 does not
    // dispatch per-family yet; this slot is reserved.
    nlmsg_ack(&hdr, 0)
}

fn handle_ctrl(req: &Nlmsghdr, gh: &Genlmsghdr, attrs: &[u8]) -> Vec<u8> {
    match gh.cmd {
        ctrl_cmd::CTRL_CMD_GETFAMILY => {
            // If a FAMILY_NAME attr is present, return that family only.
            // Otherwise return every registered family + NLMSG_DONE.
            if let Some(name) = find_family_name(attrs) {
                if let Some(fam) = lookup_family_by_name(name) {
                    return build_newfamily_reply(req.nlmsg_seq, req.nlmsg_pid, &fam);
                }
                return nlmsg_ack(req, -2 /* ENOENT */);
            }
            let mut reply: Vec<u8> = Vec::with_capacity(256);
            for fam in snapshot_families().iter() {
                let mut one = build_newfamily_reply(
                    req.nlmsg_seq, req.nlmsg_pid, fam,
                );
                // Flag each entry as part of a multi-part dump.
                if let Some(h) = Nlmsghdr::parse(&one) {
                    let mut h2 = h;
                    h2.nlmsg_flags = flags::NLM_F_MULTI;
                    h2.write_to(&mut one);
                }
                reply.extend_from_slice(&one);
            }
            let mut done_buf = [0u8; Nlmsghdr::SIZE];
            let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
            done.nlmsg_flags = flags::NLM_F_MULTI;
            done.write_to(&mut done_buf);
            reply.extend_from_slice(&done_buf);
            reply
        }
        _ => nlmsg_ack(req, -22 /* EINVAL */),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genlmsghdr_roundtrip() {
        let g = Genlmsghdr { cmd: 7, version: 2, reserved: 0 };
        let mut buf = [0u8; Genlmsghdr::SIZE];
        g.write_to(&mut buf);
        let p = Genlmsghdr::parse(&buf).unwrap();
        assert_eq!(p.cmd, 7);
        assert_eq!(p.version, 2);
    }

    #[test]
    fn register_family_idempotent() {
        let a = register_family("oxide-test-fam", 1, 0, 0);
        let b = register_family("oxide-test-fam", 1, 0, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn ctrl_family_lookup_returns_constants() {
        let f = lookup_family_by_name(CTRL_FAMILY_NAME).unwrap();
        assert_eq!(f.id, CTRL_FAMILY_ID);
        assert_eq!(f.name, CTRL_FAMILY_NAME);
    }
}
