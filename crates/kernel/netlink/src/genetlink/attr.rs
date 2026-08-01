// `nlattr` stream builder shared by every genetlink message producer.
//
// Attributes are `{u16 len; u16 type; payload}` padded to a 4-byte multiple;
// `len` counts the header but NOT the tail padding. Nests are built in place
// and back-patched, and 64-bit payloads get the padding attribute netlink
// requires so `nla_data` lands 8-byte aligned.

extern crate alloc;

use alloc::vec::Vec;

use crate::nlmsg_align;

/// `nlattr` header size.
pub const NLA_HDRLEN: usize = 4;
/// Alignment a 64-bit attribute payload must reach.
const NLA_64BIT_ALIGN: usize = 8;

/// Append one attribute with a raw payload. # C: O(payload)
pub fn put(out: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let total = NLA_HDRLEN + payload.len();
    out.extend_from_slice(&(total as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    for _ in 0..(nlmsg_align(total) - total) { out.push(0); }
}

/// Append a `u16` attribute. # C: O(1)
pub fn put_u16(out: &mut Vec<u8>, ty: u16, v: u16) { put(out, ty, &v.to_ne_bytes()); }

/// Append a `u32` attribute. # C: O(1)
pub fn put_u32(out: &mut Vec<u8>, ty: u16, v: u32) { put(out, ty, &v.to_ne_bytes()); }

/// Append a NUL-terminated string attribute. # C: O(len)
pub fn put_str(out: &mut Vec<u8>, ty: u16, s: &str) {
    let mut payload: Vec<u8> = Vec::with_capacity(s.len() + 1);
    payload.extend_from_slice(s.as_bytes());
    payload.push(0);
    put(out, ty, &payload);
}

/// Append a `u64` attribute, inserting `pad_ty` first when the payload would
/// otherwise land 4-byte aligned. An empty attribute is exactly one header, so
/// emitting it flips the alignment of everything that follows. # C: O(1)
pub fn put_u64_64bit(out: &mut Vec<u8>, ty: u16, v: u64, pad_ty: u16) {
    if out.len() % NLA_64BIT_ALIGN == 0 { put(out, pad_ty, &[]); }
    put(out, ty, &v.to_ne_bytes());
}

/// Open a nest and return the offset of its header for `nest_end`. # C: O(1)
pub fn nest_start(out: &mut Vec<u8>, ty: u16) -> usize {
    let at = out.len();
    // Length is patched by `nest_end`; type carries NLA_F_NESTED.
    out.extend_from_slice(&0u16.to_ne_bytes());
    out.extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
    at
}

/// Close the nest opened at `at`, writing its final length. # C: O(1)
pub fn nest_end(out: &mut Vec<u8>, at: usize) {
    let len = (out.len() - at) as u16;
    out[at..at + 2].copy_from_slice(&len.to_ne_bytes());
}

/// `NLA_F_NESTED` — set on every nest container's type field.
pub const NLA_F_NESTED: u16 = 1 << 15;
/// Mask that strips `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER` from a type field.
pub const NLA_TYPE_MASK: u16 = 0x3fff;

/// One decoded attribute: type (flags stripped) and payload slice.
#[derive(Clone, Copy, Debug)]
pub struct Attr<'a> {
    pub ty:      u16,
    pub payload: &'a [u8],
}

impl Attr<'_> {
    /// Payload as a `u16`, when it is exactly that wide. # C: O(1)
    pub fn u16(&self) -> Option<u16> {
        self.payload.get(..2).map(|b| u16::from_ne_bytes([b[0], b[1]]))
    }
    /// Payload as a NUL-terminated string. # C: O(len)
    pub fn nul_str(&self) -> Option<&str> {
        let end = self.payload.iter().position(|&b| b == 0)?;
        core::str::from_utf8(&self.payload[..end]).ok()
    }
}

/// Walk an attribute stream. Stops at the first malformed header, matching
/// netlink's `nla_ok` admission. # C: O(N attrs)
pub fn parse(attrs: &[u8]) -> AttrIter<'_> { AttrIter { buf: attrs, off: 0 } }

pub struct AttrIter<'a> { buf: &'a [u8], off: usize }

impl<'a> Iterator for AttrIter<'a> {
    type Item = Attr<'a>;
    fn next(&mut self) -> Option<Attr<'a>> {
        if self.off + NLA_HDRLEN > self.buf.len() { return None; }
        let len = u16::from_ne_bytes([self.buf[self.off], self.buf[self.off + 1]]) as usize;
        let ty = u16::from_ne_bytes([self.buf[self.off + 2], self.buf[self.off + 3]]) & NLA_TYPE_MASK;
        if len < NLA_HDRLEN || self.off + len > self.buf.len() { return None; }
        let payload = &self.buf[self.off + NLA_HDRLEN..self.off + len];
        self.off += nlmsg_align(len);
        Some(Attr { ty, payload })
    }
}

/// First attribute of type `ty`, if present. # C: O(N attrs)
pub fn find(attrs: &[u8], ty: u16) -> Option<Attr<'_>> { parse(attrs).find(|a| a.ty == ty) }
