// The two headers a dmesg record carries, and the parse that strips the
// outer one when the record is read back.
//
//  - the BACKEND header, written into the zone ahead of the record body:
//    `====<seconds>.<microseconds>-D\n`. It is what makes a zone's contents
//    self-describing across a reboot — the timestamp a record file reports
//    comes from here, and a dump zone whose contents do not begin with one
//    is contents this kernel did not write and is discarded.
//
//  - the CORE header, the first line of the record body:
//    `<Reason>#<count> Part<n>`. It names why the snapshot was taken.

use alloc::string::String;
use alloc::vec::Vec;

use crate::uapi::DumpReason;

const MARKER: &[u8] = b"====";

/// Microseconds per second — the header's fractional field resolution.
const USEC_PER_SEC: u64 = 1_000_000;
/// Nanoseconds per microsecond.
const NSEC_PER_USEC: u64 = 1000;

/// What a backend header said. `len` is how many bytes to skip to reach the
/// record body.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KmsgHdr {
    pub sec: u64,
    pub nsec: u32,
    pub compressed: bool,
    pub len: usize,
}

fn push_dec(s: &mut String, mut v: u64, pad: usize) {
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    if v == 0 { buf[0] = b'0'; n = 1; }
    while v > 0 { buf[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    while n < pad { buf[n] = b'0'; n += 1; }
    while n > 0 { n -= 1; s.push(buf[n] as char); }
}

/// Render the backend header for a record stamped at `sec`.`nsec`.
/// # C: O(1)
pub fn write_kmsg_hdr(sec: u64, nsec: u32) -> String {
    let mut s = String::new();
    s.push_str("====");
    push_dec(&mut s, sec, 0);
    s.push('.');
    push_dec(&mut s, (nsec as u64) / NSEC_PER_USEC, 6);
    s.push_str("-D\n");
    s
}

fn dec_at(b: &[u8], i: &mut usize) -> Option<u64> {
    let start = *i;
    let mut v: u64 = 0;
    while *i < b.len() && b[*i].is_ascii_digit() {
        v = v.checked_mul(10)?.checked_add((b[*i] - b'0') as u64)?;
        *i += 1;
    }
    if *i == start { None } else { Some(v) }
}

/// Parse a backend header off the front of `buf`.
///
/// `None` means the bytes are not a record this kernel wrote — the caller
/// discards the zone rather than publishing whatever the memory held, which
/// is what stops a stale or foreign region from appearing as a crash report.
/// Both spellings the reference accepts are accepted: with and without the
/// trailing compression flag. # C: O(header length)
pub fn parse_kmsg_hdr(buf: &[u8]) -> Option<KmsgHdr> {
    if !buf.starts_with(MARKER) { return None; }
    let mut i = MARKER.len();
    let sec = dec_at(buf, &mut i)?;
    if i >= buf.len() || buf[i] != b'.' { return None; }
    i += 1;
    let usec = dec_at(buf, &mut i)?;
    if usec >= USEC_PER_SEC { return None; }
    let mut compressed = false;
    if i < buf.len() && buf[i] == b'-' {
        i += 1;
        if i >= buf.len() { return None; }
        match buf[i] {
            b'C' => compressed = true,
            b'D' => {}
            _ => return None,
        }
        i += 1;
    }
    if i >= buf.len() || buf[i] != b'\n' { return None; }
    i += 1;
    Some(KmsgHdr { sec, nsec: (usec * NSEC_PER_USEC) as u32, compressed, len: i })
}

/// The core header line that leads a dmesg record body: why the snapshot was
/// taken, which snapshot it is, and which part. # C: O(1)
pub fn dump_header(reason: DumpReason, count: u32, part: u32) -> Vec<u8> {
    let mut s = String::new();
    s.push_str(reason.as_str());
    s.push('#');
    push_dec(&mut s, count as u64, 0);
    s.push_str(" Part");
    push_dec(&mut s, part as u64, 0);
    s.push('\n');
    s.into_bytes()
}

#[cfg(test)]
#[path = "tests/hdr.rs"]
mod tests;
