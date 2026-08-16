// Walking a netlink attribute blob. Length rules only: which attribute means
// what is the caller's business.

use syscall::errno::Errno;

use crate::uapi::{nla_align, NLA_HDR_LEN, NLA_TYPE_MASK};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Attr<'a> {
    pub ty: u16,
    pub payload: &'a [u8],
}

impl<'a> Attr<'a> {
    /// Native-order 16-bit payload. A payload too small for the type is out of
    /// range rather than invalid — the attribute is understood, its length is
    /// not one the type can have. # C: O(1)
    pub fn u16(&self) -> Result<u16, Errno> {
        if self.payload.len() < 2 { return Err(Errno::Erange); }
        Ok(u16::from_ne_bytes([self.payload[0], self.payload[1]]))
    }

    /// Network-order 16-bit payload. # C: O(1)
    pub fn be16(&self) -> Result<u16, Errno> {
        if self.payload.len() < 2 { return Err(Errno::Erange); }
        Ok(u16::from_be_bytes([self.payload[0], self.payload[1]]))
    }

    /// Native-order 32-bit payload. # C: O(1)
    pub fn u32(&self) -> Result<u32, Errno> {
        if self.payload.len() < 4 { return Err(Errno::Erange); }
        Ok(u32::from_ne_bytes([self.payload[0], self.payload[1],
                               self.payload[2], self.payload[3]]))
    }

    /// Reject a payload shorter than a fixed-width structure. # C: O(1)
    pub fn min_len(&self, len: usize) -> Result<&'a [u8], Errno> {
        if self.payload.len() < len { return Err(Errno::Erange); }
        Ok(self.payload)
    }
}

/// Walk a blob of attributes. A header that does not fit, or claims a length
/// the blob cannot hold, ends the walk with a malformed-message error.
/// # C: O(N)
pub fn for_each<'a>(blob: &'a [u8], mut f: impl FnMut(Attr<'a>) -> Result<(), Errno>)
    -> Result<(), Errno>
{
    let mut off = 0usize;
    while off + NLA_HDR_LEN <= blob.len() {
        let len = u16::from_ne_bytes([blob[off], blob[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([blob[off + 2], blob[off + 3]]) & NLA_TYPE_MASK;
        if len < NLA_HDR_LEN || off + len > blob.len() { return Err(Errno::Einval); }
        f(Attr { ty, payload: &blob[off + NLA_HDR_LEN..off + len] })?;
        off += nla_align(len);
    }
    Ok(())
}

/// Payload of the first attribute with this number. # C: O(N)
pub fn find<'a>(blob: &'a [u8], ty: u16) -> Result<Option<&'a [u8]>, Errno> {
    let mut found: Option<&'a [u8]> = None;
    for_each(blob, |a| { if a.ty == ty && found.is_none() { found = Some(a.payload); } Ok(()) })?;
    Ok(found)
}

/// Append one attribute, padded to the alignment boundary. # C: O(len)
pub fn put(out: &mut alloc::vec::Vec<u8>, ty: u16, payload: &[u8]) {
    let total = NLA_HDR_LEN + payload.len();
    out.extend_from_slice(&(total as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    for _ in total..nla_align(total) { out.push(0); }
}
