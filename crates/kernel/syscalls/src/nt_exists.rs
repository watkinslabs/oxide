//! Native Windows existence query over the Linux-shaped VFS resolver.
#![cfg(target_os = "oxide-kernel")]
use alloc::string::String;
use syscall::nt::{NtCall, NtService};

const MAX_PATH_UNITS: usize = 32767;

/// Convert a bounded UTF-16 path and query the canonical VFS namespace.
/// # C: O(path length)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlDoesFileExistsU { return None; }
    if call.args.a0 == 0 { return Some(0); }
    let mut path = String::new();
    for index in 0..MAX_PATH_UNITS {
        let address = match call.args.a0.checked_add((index * 2) as u64) { Some(value) => value, None => return Some(0) };
        let mut bytes = [0u8; 2];
        if uaccess::copy_from_user(&mut bytes, address).is_err() { return Some(0); }
        let unit = u16::from_le_bytes(bytes);
        if unit == 0 { break; }
        let Some(character) = core::char::from_u32(unit as u32) else { return Some(0); };
        path.push(character);
    }
    if path.is_empty() { return Some(0); }
    let Some(path) = crate::nt_path::normalize_path(&path) else { return Some(0); };
    Some(u64::from(crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path, vfs::LookupFlags::default()).is_ok()))
}
