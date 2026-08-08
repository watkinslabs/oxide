// `kmsg_bytes` — how much of the kernel log a dmesg record carries — and the
// mount parameter that sets it.
//
// The value is global, not per mount: it bounds what the CAPTURE writes, and
// a capture happens whether or not anything is mounted. A mount that names it
// installs the new value; a mount that does not leaves the live one alone.
//
// The admission rule here is pstore's own, and it is not the rule any other
// filesystem in this kernel follows: pstore swallows EVERY rejection. An
// unknown key, a value that is not a number, a bare word where a number was
// required — each is dropped and the mount still succeeds, changing nothing.
// A stricter table would fail mounts the reference completes.

use crate::limits::DEFAULT_KMSG_BYTES;
use core::sync::atomic::{AtomicU32, Ordering};
use vfs::fs::{FsParamSpec, FsParamType, FsParamVerdict, FsParameter, FsValue};

/// The one parameter a pstore mount takes.
pub static PSTORE_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("kmsg_bytes", FsParamType::U32),
];

static KMSG_BYTES: AtomicU32 = AtomicU32::new(DEFAULT_KMSG_BYTES);

/// How many bytes of log the next captured record carries. # C: O(1)
pub fn kmsg_bytes() -> u32 { KMSG_BYTES.load(Ordering::Acquire) }

/// Install a new bound. # C: O(1)
pub fn set_kmsg_bytes(v: u32) { KMSG_BYTES.store(v, Ordering::Release); }

/// The value one mount's options ask for, or `None` when the mount named
/// nothing usable — in which case the live value stands.
///
/// Every rejection is swallowed, so this function has no error return at all.
/// # C: O(len data * N_specs)
pub fn kmsg_bytes_for_mount(data: &str, pinned: &[FsParameter]) -> Option<u32> {
    let mut out = None;
    for p in vfs::fs::split_monolithic(data) {
        if let Some(v) = admit_one(&p) { out = Some(v); }
    }
    for p in pinned {
        if let Some(v) = admit_one(p) { out = Some(v); }
    }
    out
}

fn admit_one(p: &FsParameter) -> Option<u32> {
    match vfs::fs::admit_fs_param(PSTORE_PARAMS, p) {
        FsParamVerdict::Accept(_) => {}
        // Unknown key, or a declared key given the wrong value shape: both are
        // the reference's negative parse result, and both are dropped.
        FsParamVerdict::Unknown | FsParamVerdict::WrongValueShape(_) => return None,
    }
    let s = match &p.value { FsValue::String(s) => s.as_str(), _ => return None };
    parse_u32(s)
}

/// The reference's `u32` parameter value: decimal, or hexadecimal with an
/// `0x` prefix. Anything else is not a number and is dropped. # C: O(len)
fn parse_u32(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    s.parse::<u32>().ok()
}

/// Where in the log stream a record's contents start, and how long they are.
///
/// `total` is the running byte count of everything ever logged. A record
/// carries the NEWEST bytes: the tail bounded by `bytes`, further bounded by
/// the room a zone has left after its headers. This is the whole effect of
/// `kmsg_bytes` — shrink it and the next record contains less.
/// # C: O(1)
pub fn capture_window(total: usize, bytes: u32, room: usize) -> (usize, usize) {
    let want = core::cmp::min(bytes as usize, room);
    let len = core::cmp::min(want, total);
    (total - len, len)
}

/// Render for `/proc/mounts`: the reference shows the option only when it
/// differs from the built-in default. # C: O(1)
pub fn show_options() -> alloc::string::String {
    use alloc::string::String;
    let v = kmsg_bytes();
    if v == DEFAULT_KMSG_BYTES { return String::new(); }
    let mut s = String::from(",kmsg_bytes=");
    let mut buf = [0u8; 10];
    let mut n = 0usize;
    let mut x = v;
    if x == 0 { buf[0] = b'0'; n = 1; }
    while x > 0 { buf[n] = b'0' + (x % 10) as u8; x /= 10; n += 1; }
    while n > 0 { n -= 1; s.push(buf[n] as char); }
    s
}

#[cfg(test)]
#[path = "tests/kmsg.rs"]
mod tests;
