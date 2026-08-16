//! Extended inquiry / advertising data: a run of `[len][type][value]` fields.
//!
//! `len` counts the type byte, so a field occupies `len + 1` bytes and an empty
//! field is `len == 1`. Two things end a walk: a zero length, which is the
//! padding that fills the rest of a fixed-size buffer, and a length claiming
//! more bytes than remain, which is a malformed field. Neither is a reason to
//! read past the buffer, and the bound below is the only thing standing between
//! a hostile advertisement and the bytes after it.

use alloc::vec::Vec;

use crate::uapi::hci::EIR_SERVICE_DATA;

/// Bytes a field of `data_len` value bytes occupies. # C: O(1)
pub fn precalc_len(data_len: usize) -> usize { 2 + data_len }

/// Largest value a single field can carry: the length byte counts the type. # C: O(1)
pub const EIR_MAX_FIELD_DATA: usize = u8::MAX as usize - 1;

/// Append one field. Refuses a value too long to describe in the length byte
/// rather than writing a field whose length wraps. # C: O(n)
pub fn append_data(out: &mut Vec<u8>, ad_type: u8, data: &[u8]) -> bool {
    if data.len() > EIR_MAX_FIELD_DATA { return false; }
    out.push((data.len() + 1) as u8);
    out.push(ad_type);
    out.extend_from_slice(data);
    true
}

/// Append a field whose value is one little-endian 16-bit word. # C: O(1)
pub fn append_le16(out: &mut Vec<u8>, ad_type: u8, value: u16) {
    out.push(3);
    out.push(ad_type);
    out.extend_from_slice(&value.to_le_bytes());
}

/// Walk over the fields of an EIR buffer.
pub struct EirIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> EirIter<'a> {
    /// # C: O(1)
    pub fn new(buf: &'a [u8]) -> EirIter<'a> { EirIter { buf, pos: 0 } }

    /// Offset the walk stopped at, which is the length of the meaningful
    /// prefix once iteration ends. # C: O(1)
    pub fn offset(&self) -> usize { self.pos }
}

impl<'a> Iterator for EirIter<'a> {
    type Item = (u8, &'a [u8]);

    /// Next `(type, value)`. Stops at a zero length or at a field claiming more
    /// bytes than remain; never reads past the buffer. # C: O(1)
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        // A field needs at least its length and type bytes.
        if self.pos + 1 >= self.buf.len() { return None; }
        let field_len = self.buf[self.pos] as usize;
        if field_len == 0 { return None; }
        let end = self.pos + 1 + field_len;
        if end > self.buf.len() { return None; }
        let ad_type = self.buf[self.pos + 1];
        let value = &self.buf[self.pos + 2..end];
        self.pos = end;
        Some((ad_type, value))
    }
}

/// Value of the first field of `ad_type`. A field present but empty is reported
/// as absent, matching what a client sees for a type it never sent. # C: O(n)
pub fn get_data(eir: &[u8], ad_type: u8) -> Option<&[u8]> {
    EirIter::new(eir).find(|(t, v)| *t == ad_type && !v.is_empty()).map(|(_, v)| v)
}

/// Service data for one 16-bit UUID: the value of a service-data field whose
/// first two bytes name it. # C: O(n)
pub fn get_service_data(eir: &[u8], uuid: u16) -> Option<&[u8]> {
    for (t, v) in EirIter::new(eir) {
        if t != EIR_SERVICE_DATA || v.len() < 2 { continue; }
        if u16::from_le_bytes([v[0], v[1]]) == uuid { return Some(&v[2..]); }
    }
    None
}

/// Whether every field in the buffer is well formed to its end, allowing a
/// zero-length terminator and the padding after it. A buffer that stops early
/// on a field claiming more bytes than remain is not. # C: O(n)
pub fn is_well_formed(eir: &[u8]) -> bool {
    let mut it = EirIter::new(eir);
    while it.next().is_some() {}
    let pos = it.offset();
    // Either every byte was consumed, or the walk stopped on a zero length
    // whose remaining bytes are padding rather than a truncated field.
    pos == eir.len() || eir[pos] == 0
}

#[cfg(test)]
#[path = "tests/eir.rs"]
mod tests;
