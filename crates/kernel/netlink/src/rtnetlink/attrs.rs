extern crate alloc;

use alloc::vec::Vec;

use crate::nlmsg_align;

/// `struct nlattr` is 4-byte header { u16 nla_len; u16 nla_type }
/// followed by the payload, rounded up to NLA_ALIGNTO (4).
/// `nla_len` covers the header + payload but NOT the trailing pad.
/// # C: O(N) memcpy
pub fn put_nlattr(out: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let total = 4 + payload.len();
    out.extend_from_slice(&(total as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    let pad = nlmsg_align(total) - total;
    for _ in 0..pad { out.push(0); }
}

/// # C: O(1)
pub fn put_nlattr_u32(out: &mut Vec<u8>, ty: u16, v: u32) {
    put_nlattr(out, ty, &v.to_ne_bytes());
}

/// # C: O(1)
pub fn put_nlattr_u8(out: &mut Vec<u8>, ty: u16, v: u8) {
    put_nlattr(out, ty, &[v]);
}

/// `nla_put_string` per Linux — NUL-terminated.
/// # C: O(N)
pub fn put_nlattr_str(out: &mut Vec<u8>, ty: u16, s: &str) {
    let mut payload: Vec<u8> = Vec::with_capacity(s.len() + 1);
    payload.extend_from_slice(s.as_bytes());
    payload.push(0);
    put_nlattr(out, ty, &payload);
}
