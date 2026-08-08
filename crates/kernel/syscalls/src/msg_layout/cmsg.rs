// Ancillary-data conversion between the two message ABIs.
//
// A `cmsghdr` differs by more than field width: the 32-bit form is 12 bytes
// and aligns each entry to 4, the native form is 16 bytes and aligns to 8. So
// a compat control stream is not a native one with narrower fields — the
// entries sit at different offsets and the whole stream has to be rebuilt
// before any protocol parses it, and rebuilt back for a receive.

use alloc::vec::Vec;

use syscall::errno::Errno;

use super::MsgLayout;

/// Offsets inside one `cmsghdr`: the length is one ABI word, the level and
/// type are `int` on both.
const LEVEL_AFTER_LEN: usize = 0;
const TYPE_AFTER_LEVEL: usize = core::mem::size_of::<i32>();

/// One control entry's header bytes in `layout`'s shape. `len` is the
/// `cmsg_len` value — header plus emitted data, unaligned, exactly as the
/// receiver reads it. # C: O(1)
pub fn header_bytes(layout: MsgLayout, len: usize, level: i32, ty: i32) -> Vec<u8> {
    let word = layout.word();
    let mut out = alloc::vec![0u8; layout.cmsghdr_size()];
    out[..word].copy_from_slice(&layout.word_bytes(len as u64)[..word]);
    out[word + LEVEL_AFTER_LEN..word + LEVEL_AFTER_LEN + 4].copy_from_slice(&level.to_ne_bytes());
    let ty_at = word + LEVEL_AFTER_LEN + TYPE_AFTER_LEVEL;
    out[ty_at..ty_at + 4].copy_from_slice(&ty.to_ne_bytes());
    out
}

/// One entry of a walked control stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Byte offset of the entry's header within the stream.
    pub at: usize,
    /// `cmsg_len` as the sender wrote it.
    pub len: usize,
    pub level: i32,
    pub ty: i32,
}

impl Entry {
    /// The entry's payload bytes within the stream it was walked from.
    /// # C: O(1)
    pub fn data<'a>(&self, layout: MsgLayout, stream: &'a [u8]) -> &'a [u8] {
        let from = self.at + layout.cmsghdr_size();
        &stream[from..from + (self.len - layout.cmsghdr_size())]
    }
}

/// Walk one control stream in `layout`'s shape.
///
/// The bounds are the sender's: an entry is well formed when its `cmsg_len`
/// covers at least a header and does not run past the end of the control
/// buffer measured from that entry. A malformed one fails the whole send with
/// EINVAL rather than being skipped. The walk stops when the next aligned
/// header offset is no longer inside the buffer — a trailing remnant too
/// short to hold a header is not an entry and not an error.
/// # C: O(entries)
pub fn walk(layout: MsgLayout, stream: &[u8]) -> Result<Vec<Entry>, Errno> {
    let hdr = layout.cmsghdr_size();
    let mut out = Vec::new();
    if stream.len() < hdr { return Ok(out); }
    let mut at = 0usize;
    while at < stream.len() {
        // A header that does not fit cannot describe a well-formed entry: any
        // value read there would have to be <= the bytes left, which is fewer
        // than one header, so the sender's stream is malformed.
        if at + hdr > stream.len() { return Err(Errno::Einval); }
        let len = layout.word_at(stream, at) as usize;
        if len < hdr || len > stream.len() - at { return Err(Errno::Einval); }
        let level = i32::from_ne_bytes(
            stream[at + layout.word()..at + layout.word() + 4].try_into().unwrap());
        let ty_at = at + layout.word() + TYPE_AFTER_LEVEL;
        let ty = i32::from_ne_bytes(stream[ty_at..ty_at + 4].try_into().unwrap());
        out.push(Entry { at, len, level, ty });
        let Some(next) = at.checked_add(layout.cmsg_aligned(len)) else { break };
        if next <= at { break; }
        at = next;
    }
    Ok(out)
}

/// Rebuild a 32-bit sender's control stream in native form, so the protocol
/// layers that parse ancillary data only ever see one shape.
///
/// A stream that yields no entry at all is EINVAL: a caller that supplied a
/// control length but no readable control message did not send what it meant
/// to, and silently sending nothing would hide it.
/// # C: O(bytes)
pub fn compat_to_native(stream: &[u8]) -> Result<Vec<u8>, Errno> {
    let compat = MsgLayout::Compat;
    let native = MsgLayout::Native;
    let entries = walk(compat, stream)?;
    let mut total = 0usize;
    for entry in &entries {
        let native_len = entry.len - compat.cmsghdr_size() + native.cmsghdr_size();
        total = total.checked_add(native.cmsg_aligned(native_len)).ok_or(Errno::Einval)?;
    }
    if total == 0 { return Err(Errno::Einval); }
    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| Errno::Enomem)?;
    out.resize(total, 0);
    let mut at = 0usize;
    for entry in &entries {
        let data = entry.data(compat, stream);
        let native_len = native.cmsghdr_size() + data.len();
        let advance = native.cmsg_aligned(native_len);
        if total - at < advance { return Err(Errno::Einval); }
        let header = header_bytes(native, native_len, entry.level, entry.ty);
        out[at..at + header.len()].copy_from_slice(&header);
        out[at + header.len()..at + native_len].copy_from_slice(data);
        at += advance;
    }
    if at != total { return Err(Errno::Einval); }
    Ok(out)
}
