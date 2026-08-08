// A captured record and the name its file carries.

use alloc::string::String;
use alloc::vec::Vec;

use crate::uapi::RecordType;

/// What identifies one record inside a backend: its class and which zone of
/// that class holds it. Together with the backend name this is what the
/// filename spells, and what unlinking the file erases.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RecordId {
    pub ty: RecordType,
    pub index: usize,
}

/// One surviving record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub id: RecordId,
    /// When the record was captured, as seconds and nanoseconds of wall
    /// clock. Zero for a class that carries no timestamp of its own — the
    /// reference leaves a console record's time at zero for the same reason.
    pub sec: u64,
    pub nsec: u32,
    pub body: Vec<u8>,
}

/// The filename a record appears under: `<type>-<backend>-<index>`. A
/// crash-report collector globs for exactly this. # C: O(1)
pub fn file_name(id: RecordId, backend: &str) -> String {
    let mut s = String::new();
    s.push_str(id.ty.name());
    s.push('-');
    s.push_str(backend);
    s.push('-');
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    let mut v = id.index as u64;
    if v == 0 { buf[0] = b'0'; n = 1; }
    while v > 0 { buf[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    while n > 0 { n -= 1; s.push(buf[n] as char); }
    s
}

#[cfg(test)]
#[path = "tests/record.rs"]
mod tests;
