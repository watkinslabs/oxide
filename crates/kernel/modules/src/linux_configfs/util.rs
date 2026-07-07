use alloc::string::String;
use core::ffi::c_char;
use vfs::{KResult, VfsError};

pub(super) fn checked_size(v: isize) -> KResult<usize> {
    if v < 0 { Err(errno_to_vfs((-v) as i32)) } else { Ok(v as usize) }
}

pub(super) fn errno_to_vfs(e: i32) -> VfsError { match e {
    2 => VfsError::Enoent, 12 => VfsError::Enomem, 13 => VfsError::Eacces,
    16 => VfsError::Ebusy, 17 => VfsError::Eexist, 20 => VfsError::Enotdir,
    22 => VfsError::Einval, 39 => VfsError::Enotempty, _ => VfsError::Eio,
} }

pub(super) fn read_at(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let off = off as usize;
    if off >= body.len() { return 0; }
    let n = (body.len() - off).min(buf.len());
    buf[..n].copy_from_slice(&body[off..off + n]); n
}

pub(super) fn read_cstr(ptr: *const c_char, max: usize) -> Option<String> {
    if ptr.is_null() { return None; }
    let mut bytes = alloc::vec::Vec::new();
    for i in 0..=max {
        // SAFETY: caller passes a NUL-terminated C string; bounded scan avoids unbounded reads.
        let b = unsafe { *ptr.add(i) } as u8;
        if b == 0 { return String::from_utf8(bytes).ok(); }
        bytes.push(b);
    }
    None
}

pub(super) fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.as_bytes().iter().any(|b| *b == b'/')
}

pub(super) fn join_path(parent: &str, name: &str) -> String {
    let mut p = String::from(parent);
    if !p.is_empty() { p.push('/'); } p.push_str(name); p
}
