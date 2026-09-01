//! Native DOS search-path resolution over the Linux-shaped VFS namespace.
#![cfg(target_os = "oxide-kernel")]
use alloc::{string::String, vec::Vec};
use syscall::nt::{NtCall, NtService};

const MAX_PATH_UNITS: usize = 32767;

/// Search a semicolon-separated path list and return a UTF-16 result.
/// # C: O(path entries × path length)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlDosSearchPathU { return None; }
    let paths = read_wide(call.args.a0)?;
    let search = read_wide(call.args.a1)?;
    let extension = if call.args.a2 == 0 { String::new() } else { read_wide(call.args.a2)? };
    if search.is_empty() { return Some(0); }
    let relative = !search.contains(['\\', '/', ':']);
    let mut candidates = Vec::new();
    if !relative { candidates.push(search.clone()); }
    else {
        for directory in paths.split(';') {
            if directory.is_empty() { continue; }
            let mut candidate = String::from(directory);
            if !candidate.ends_with(['\\', '/']) { candidate.push('\\'); }
            candidate.push_str(&search);
            if !search.contains('.') { candidate.push_str(&extension); }
            candidates.push(candidate);
        }
    }
    let found = candidates.into_iter().find(|candidate| {
        let Some(path) = crate::nt_path::normalize_path(candidate) else { return false; };
        crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path, vfs::LookupFlags::default()).is_ok()
    });
    let Some(found) = found else { return Some(0); };
    let units: Vec<u16> = found.encode_utf16().collect();
    let required = units.len() + 1;
    if call.args.a3 < required as u64 { return Some(required as u64); }
    if call.args.a4 == 0 { return Some(0); }
    let mut bytes = Vec::with_capacity(required * 2);
    for unit in &units { bytes.extend_from_slice(&unit.to_le_bytes()); }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    if uaccess::copy_to_user(call.args.a4, &bytes).is_err() { return Some(0); }
    if call.args.a5 != 0 {
        let part = found.rfind(['\\', '/']).map_or(0, |index| index + 1);
        let _ = uaccess::put_user_u64(call.args.a5, call.args.a4 + (part * 2) as u64);
    }
    Some(units.len() as u64)
}

fn read_wide(address: u64) -> Option<String> {
    if address == 0 { return None; }
    let mut output = String::new();
    for index in 0..MAX_PATH_UNITS {
        let address = address.checked_add((index * 2) as u64)?;
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes, address).ok()?;
        let unit = u16::from_le_bytes(bytes);
        if unit == 0 { return Some(output); }
        output.push(core::char::from_u32(unit as u32)?);
    }
    None
}
