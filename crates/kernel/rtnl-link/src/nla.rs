//! Netlink attribute walking. Every length here is attacker-controlled, so a
//! malformed blob must end the walk rather than index past its end or loop.

use crate::uapi::*;

/// One attribute: its number with the flag bits stripped, and its payload.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Attr<'a> { pub ty: u16, pub nested: bool, pub payload: &'a [u8] }

impl<'a> Attr<'a> {
    /// Payload as a native-order u16, `None` when it is the wrong width. # C: O(1)
    pub fn u16(&self) -> Option<u16> {
        if self.payload.len() < 2 { return None; }
        Some(u16::from_ne_bytes([self.payload[0], self.payload[1]]))
    }
    /// # C: O(1)
    pub fn u32(&self) -> Option<u32> {
        if self.payload.len() < 4 { return None; }
        Some(u32::from_ne_bytes([self.payload[0], self.payload[1],
                                 self.payload[2], self.payload[3]]))
    }
    /// Payload as a NUL-terminated string. A payload with no terminator is
    /// refused rather than read to its end: the sender declared a C string.
    /// # C: O(len)
    pub fn cstr(&self) -> Option<&'a str> {
        let end = self.payload.iter().position(|&b| b == 0)?;
        core::str::from_utf8(&self.payload[..end]).ok()
    }
}

/// Round a length up to the attribute alignment. # C: O(1)
pub const fn align(n: usize) -> usize { (n + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1) }

/// Walk one attribute blob. Stops at the first malformed header, which is what
/// keeps a truncated or lying length from being read past.
/// # C: O(len(blob))
pub fn for_each<'a, F: FnMut(Attr<'a>)>(blob: &'a [u8], mut f: F) {
    let mut off = 0;
    while off + NLA_HDR_LEN <= blob.len() {
        let len = u16::from_ne_bytes([blob[off], blob[off + 1]]) as usize;
        let raw = u16::from_ne_bytes([blob[off + 2], blob[off + 3]]);
        if len < NLA_HDR_LEN || off + len > blob.len() { return; }
        f(Attr { ty: raw & NLA_TYPE_MASK, nested: raw & NLA_F_NESTED != 0,
                 payload: &blob[off + NLA_HDR_LEN..off + len] });
        let next = off + align(len);
        // An attribute whose aligned length is zero would spin forever.
        if next <= off { return; }
        off = next;
    }
}

/// First attribute with a given number. # C: O(len(blob))
pub fn find<'a>(blob: &'a [u8], ty: u16) -> Option<Attr<'a>> {
    let mut out = None;
    for_each(blob, |a| if a.ty == ty && out.is_none() { out = Some(a) });
    out
}

/// Append one attribute. # C: O(len(payload))
pub fn put(out: &mut alloc::vec::Vec<u8>, ty: u16, payload: &[u8]) {
    let len = NLA_HDR_LEN + payload.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align(out.len()), 0);
}

/// Open a nest; returns the offset whose length must be patched. # C: O(1)
pub fn nest_start(out: &mut alloc::vec::Vec<u8>, ty: u16) -> usize {
    let at = out.len();
    out.extend_from_slice(&0u16.to_ne_bytes());
    out.extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
    at
}

/// Close a nest. # C: O(1)
pub fn nest_end(out: &mut alloc::vec::Vec<u8>, at: usize) {
    let len = (out.len() - at) as u16;
    out[at..at + 2].copy_from_slice(&len.to_ne_bytes());
}
