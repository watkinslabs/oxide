// Building a request and reading a reply back: the two halves of driving a
// command handler without a socket underneath it.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;
use netlink::genetlink::family::GenlCtx;
use netlink::genetlink::uapi::Genlmsghdr;
use netlink::{flags, msg as nlmsg, Nlmsghdr};
use syscall::errno::Errno;

use crate::ieee80211::MacAddr;
use crate::wdev::Wdev;
use crate::wiphy::Wiphy;

use super::{NS, PORT};

/// A request under construction.
pub struct Req {
    pub hdr: Nlmsghdr,
    pub attrs: Vec<u8>,
}

impl Req {
    /// A request addressed to a radio. # C: O(1)
    pub fn wiphy(w: &Arc<Wiphy>) -> Self {
        let mut r = Self::bare();
        r.u32(crate::uapi::attr::WIPHY, w.index);
        r
    }
    /// A request addressed to an interface. # C: O(1)
    pub fn wdev(d: &Arc<Wdev>) -> Self {
        let mut r = Self::bare();
        r.u64(crate::uapi::attr::WDEV, d.identifier);
        r
    }
    /// A request addressing nothing. # C: O(1)
    pub fn bare() -> Self {
        Self {
            hdr: Nlmsghdr { nlmsg_len: 0, nlmsg_type: 0, nlmsg_flags: flags::NLM_F_REQUEST,
                            nlmsg_seq: 9, nlmsg_pid: PORT },
            attrs: Vec::new(),
        }
    }
    /// Mark the request a dump. # C: O(1)
    pub fn dump(mut self) -> Self { self.hdr.nlmsg_flags |= flags::NLM_F_DUMP; self }

    pub fn u8(&mut self, ty: u16, v: u8) -> &mut Self { attr::put(&mut self.attrs, ty, &[v]); self }
    pub fn u16(&mut self, ty: u16, v: u16) -> &mut Self {
        attr::put_u16(&mut self.attrs, ty, v); self
    }
    pub fn u32(&mut self, ty: u16, v: u32) -> &mut Self {
        attr::put_u32(&mut self.attrs, ty, v); self
    }
    pub fn u64(&mut self, ty: u16, v: u64) -> &mut Self {
        crate::nl80211::msg::put_u64(&mut self.attrs, ty, v, crate::uapi::attr::PAD); self
    }
    pub fn bytes(&mut self, ty: u16, v: &[u8]) -> &mut Self {
        attr::put(&mut self.attrs, ty, v); self
    }
    pub fn text(&mut self, ty: u16, v: &str) -> &mut Self {
        attr::put_str(&mut self.attrs, ty, v); self
    }
    pub fn flag(&mut self, ty: u16) -> &mut Self { attr::put(&mut self.attrs, ty, &[]); self }
    pub fn mac(&mut self, ty: u16, v: MacAddr) -> &mut Self {
        attr::put(&mut self.attrs, ty, &v.0); self
    }
    /// Open a nest, fill it with `f`, and close it. # C: O(f)
    pub fn nest(&mut self, ty: u16, f: impl FnOnce(&mut Vec<u8>)) -> &mut Self {
        let at = attr::nest_start(&mut self.attrs, ty);
        f(&mut self.attrs);
        attr::nest_end(&mut self.attrs, at);
        self
    }
    /// The context a handler is called with. # C: O(1)
    pub fn ctx(&self) -> GenlCtx {
        GenlCtx { net_ns: NS, portid: self.hdr.nlmsg_pid, family_id: 0,
                  init_ns_net_admin: true, sock_ns_net_admin: true }
    }
    /// Send the request to a handler. # C: O(handler)
    pub fn call(&self, h: fn(&Nlmsghdr, &[u8], GenlCtx) -> Vec<u8>) -> Reply {
        Reply(h(&self.hdr, &self.attrs, self.ctx()))
    }
}

/// A reply, for reading back what a handler decided.
pub struct Reply(pub Vec<u8>);

impl Reply {
    /// The errno an error reply carries, as its positive number; `None` if
    /// the reply is not an error at all. # C: O(1)
    pub fn errno(&self) -> Option<i32> {
        let hdr = Nlmsghdr::parse(&self.0)?;
        if hdr.nlmsg_type != nlmsg::NLMSG_ERROR { return None; }
        let b = self.0.get(Nlmsghdr::SIZE..Nlmsghdr::SIZE + 4)?;
        let code = i32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
        if code == 0 { return None; }
        Some(-code)
    }
    /// Whether the reply refused with one particular errno. # C: O(1)
    pub fn is_err(&self, e: Errno) -> bool { self.errno() == Some(e.as_i32()) }
    /// Whether the reply is a plain acknowledgement. # C: O(1)
    pub fn is_ack(&self) -> bool {
        Nlmsghdr::parse(&self.0).is_some_and(|h| h.nlmsg_type == nlmsg::NLMSG_ERROR)
            && self.errno().is_none()
    }
    /// The command a single-message reply carries. # C: O(1)
    pub fn cmd(&self) -> Option<u8> {
        Genlmsghdr::parse(self.0.get(Nlmsghdr::SIZE..)?).map(|g| g.cmd)
    }
    /// The attribute stream of a single-message reply. # C: O(1)
    pub fn body(&self) -> &[u8] {
        let at = Nlmsghdr::SIZE + Genlmsghdr::SIZE;
        self.0.get(at..).unwrap_or(&[])
    }
    /// The attribute stream of every message in a multi-part reply,
    /// terminator excluded. # C: O(len)
    pub fn parts(&self) -> Vec<&[u8]> {
        self.walk().into_iter().map(|(_, body)| body).collect()
    }
    /// The command number of every message in a multi-part reply. # C: O(len)
    pub fn part_cmds(&self) -> Vec<u8> {
        self.walk().into_iter().map(|(c, _)| c).collect()
    }
    /// Command number and attribute stream of each part. # C: O(len)
    fn walk(&self) -> Vec<(u8, &[u8])> {
        let mut out: Vec<(u8, &[u8])> = Vec::new();
        let mut off = 0usize;
        while let Some(h) = Nlmsghdr::parse(&self.0[off.min(self.0.len())..]) {
            let len = h.nlmsg_len as usize;
            if len < Nlmsghdr::SIZE || off + len > self.0.len() { break; }
            if h.nlmsg_type == nlmsg::NLMSG_DONE { break; }
            let at = off + Nlmsghdr::SIZE;
            let cmd = Genlmsghdr::parse(&self.0[at..off + len]).map_or(0, |g| g.cmd);
            out.push((cmd, &self.0[at + Genlmsghdr::SIZE..off + len]));
            off += (len + 3) & !3;
        }
        out
    }
    /// Whether the reply ends with the multi-part terminator. # C: O(len)
    pub fn is_done(&self) -> bool {
        let mut off = 0usize;
        while let Some(h) = Nlmsghdr::parse(&self.0[off.min(self.0.len())..]) {
            let len = h.nlmsg_len as usize;
            if len < Nlmsghdr::SIZE || off + len > self.0.len() { return false; }
            if h.nlmsg_type == nlmsg::NLMSG_DONE {
                return h.nlmsg_flags & flags::NLM_F_MULTI != 0;
            }
            off += (len + 3) & !3;
        }
        false
    }
}

/// A payload of an attribute in a stream, whatever its shape. # C: O(N attrs)
pub fn find<'a>(attrs: &'a [u8], ty: u16) -> Option<&'a [u8]> {
    attr::find(attrs, ty).map(|a| a.payload)
}

/// Whether a flag attribute is present. # C: O(N attrs)
pub fn has(attrs: &[u8], ty: u16) -> bool { attr::find(attrs, ty).is_some() }

/// A `u32` attribute's value. # C: O(N attrs)
pub fn u32_of(attrs: &[u8], ty: u16) -> Option<u32> {
    let p = find(attrs, ty)?;
    Some(u32::from_ne_bytes(p.get(..4)?.try_into().ok()?))
}

/// A `u16` attribute's value. # C: O(N attrs)
pub fn u16_of(attrs: &[u8], ty: u16) -> Option<u16> {
    let p = find(attrs, ty)?;
    Some(u16::from_ne_bytes(p.get(..2)?.try_into().ok()?))
}

/// A `u8` attribute's value. # C: O(N attrs)
pub fn u8_of(attrs: &[u8], ty: u16) -> Option<u8> { find(attrs, ty)?.first().copied() }

/// Every nest inside a nest, in order, with the number each was written
/// under. # C: O(N attrs)
pub fn children(nest: &[u8]) -> Vec<(u16, &[u8])> {
    attr::parse(nest).map(|a| (a.ty, a.payload)).collect()
}

/// A well-formed management frame from `sa` with a subtype and body.
/// # C: O(len)
pub fn mgmt_frame(subtype: u16, sa: MacAddr, da: MacAddr, body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let fc = crate::ieee80211::fctl::FTYPE_MGMT | subtype;
    out.extend_from_slice(&fc.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&da.0);
    out.extend_from_slice(&sa.0);
    out.extend_from_slice(&da.0);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(body);
    out
}
