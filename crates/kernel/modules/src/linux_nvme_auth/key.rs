use core::ffi::c_char;
use core::{mem::size_of, ptr};
use super::hmac::{cstr, hash_len, hmac_once, EINVAL};

const ENOMEM: i32 = 12;
const ENOKEY: i32 = 126;
const EKEYREJECTED: i32 = 129;
const KEY_OFFSET: usize = size_of::<usize>() + size_of::<u8>();
const KEY_ALIGN: usize = size_of::<usize>();
const KEY_STRUCT_SIZE: usize = size_of::<DhchapKey>();

#[repr(C)]
pub struct DhchapKey { pub len: usize, pub hash: u8, pub key: [u8; 0] }

/// Register decoded-secret and transformed-key API symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("nvme_auth_key_struct_size", nvme_auth_key_struct_size as *const () as usize),
        ("nvme_auth_alloc_key", nvme_auth_alloc_key as *const () as usize),
        ("nvme_auth_free_key", nvme_auth_free_key as *const () as usize),
        ("nvme_auth_extract_key", nvme_auth_extract_key as *const () as usize),
        ("nvme_auth_generate_key", nvme_auth_generate_key as *const () as usize),
        ("nvme_auth_parse_key", nvme_auth_parse_key as *const () as usize),
        ("nvme_auth_transform_key", nvme_auth_transform_key as *const () as usize),
    ] { export(name, addr, true); }
}

extern "C" fn nvme_auth_key_struct_size(len: u32) -> u32 { KEY_STRUCT_SIZE.wrapping_add(len as usize) as u32 }
extern "C" fn nvme_auth_alloc_key(len: u32, hash: u8) -> *mut DhchapKey {
    let Some(total) = KEY_STRUCT_SIZE.checked_add(len as usize) else { return ptr::null_mut(); };
    let raw = crate::linux_alloc::alloc_bytes(total, KEY_ALIGN, true);
    if raw.is_null() { return ptr::null_mut(); }
    let key = raw.cast::<DhchapKey>();
    // SAFETY: alloc_bytes returned sizeof(DhchapKey) + len zeroed bytes aligned for DhchapKey.
    unsafe { (*key).len = len as usize; (*key).hash = hash; }
    key
}
extern "C" fn nvme_auth_free_key(key: *mut DhchapKey) {
    if key.is_null() { return; }
    // SAFETY: caller provides a live allocation returned by nvme_auth_alloc_key.
    unsafe { let n = KEY_STRUCT_SIZE.saturating_add((*key).len); ptr::write_bytes(key.cast::<u8>(), 0, n); crate::linux_alloc::kfree(key.cast()); }
}
extern "C" fn nvme_auth_extract_key(secret: *const c_char, hash: u8) -> *mut DhchapKey {
    let Some(secret) = cstr(secret) else { return err(EINVAL); };
    let enc = secret.iter().position(|b| *b == b':').map_or(secret, |n| &secret[..n]);
    let mut decoded = [0u8; 68]; let Some(n) = b64_decode(enc, &mut decoded) else { return err(EINVAL); };
    if !matches!(n, 36 | 52 | 68) { return err(EINVAL); }
    let data_len = n - 4;
    let want = u32::from_le_bytes(decoded[data_len..n].try_into().unwrap());
    if crc::crc32_update(u32::MAX, &decoded[..data_len]) ^ u32::MAX != want { return err(EKEYREJECTED); }
    let out = nvme_auth_alloc_key(data_len as u32, hash);
    if out.is_null() { return err(ENOMEM); }
    // SAFETY: out owns data_len flexible bytes immediately after the DhchapKey prefix.
    unsafe { ptr::copy_nonoverlapping(decoded.as_ptr(), key_bytes(out), data_len); }
    out
}
extern "C" fn nvme_auth_parse_key(secret: *const c_char, ret: *mut *mut DhchapKey) -> i32 {
    if ret.is_null() { return -EINVAL; }
    if secret.is_null() { // SAFETY: `ret` was checked non-null at entry and the
        // Linux KPI makes it a caller-owned out-parameter slot for one key pointer.
        unsafe { *ret = ptr::null_mut(); }; return 0;
    }
    let Some(s) = cstr(secret) else { return -EINVAL; };
    if s.len() < 10 || &s[..7] != b"DHHC-1:" || s[9] != b':' { return -EINVAL; }
    let hash = match (s[7], s[8]) { (a @ b'0'..=b'9', b @ b'0'..=b'9') => (a - b'0') * 10 + (b - b'0'), _ => return -EINVAL };
    // SAFETY: s.len() >= 10 was just checked and s is the same NUL-terminated buffer cstr(secret) read from, so secret+10 lands within that allocation, at worst on the terminating NUL.
    let p = unsafe { secret.add(10) }; let key = nvme_auth_extract_key(p, hash);
    // SAFETY: ret was checked non-null and receives null on the error path.
    unsafe { *ret = if is_err(key) { ptr::null_mut() } else { key }; }
    if is_err(key) { -ptr_errno(key) } else { 0 }
}
extern "C" fn nvme_auth_generate_key(secret: *const u8, ret: *mut *mut DhchapKey) -> i32 { nvme_auth_parse_key(secret.cast(), ret) }
extern "C" fn nvme_auth_transform_key(key: *const DhchapKey, nqn: *const c_char) -> *mut DhchapKey {
    if key.is_null() { return err(ENOKEY); }
    // SAFETY: key is a live DhchapKey with len key bytes.
    let (len, hash, raw) = unsafe { ((*key).len, (*key).hash, core::slice::from_raw_parts(key_bytes(key.cast_mut()), (*key).len)) };
    if hash == 0 { let out = nvme_auth_alloc_key(len as u32, hash); if out.is_null() { return err(ENOMEM); }
        // SAFETY: `out` was just allocated for `len` bytes by nvme_auth_alloc_key, so
        // its flexible array at KEY_OFFSET has room for the whole untransformed key.
        unsafe { ptr::copy_nonoverlapping(raw.as_ptr(), key_bytes(out), len); } return out; }
    let Some(nqn) = cstr(nqn) else { return err(EINVAL); }; let n = hash_len(hash); if n == 0 { return err(EINVAL); }
    let out = nvme_auth_alloc_key(n as u32, hash); if out.is_null() { return err(ENOMEM); }
    let mut message = [0u8; 4096]; if nqn.len().saturating_add(17) > message.len() { nvme_auth_free_key(out); return err(EINVAL); }
    message[..nqn.len()].copy_from_slice(nqn); message[nqn.len()..nqn.len() + 17].copy_from_slice(b"NVMe-over-Fabrics");
    // SAFETY: out was just allocated above by nvme_auth_alloc_key(n, hash), so it owns n flexible bytes starting at KEY_OFFSET, matching key_bytes' contract.
    let r = hmac_once(hash, Some(raw), Some(&message[..nqn.len() + 17]), unsafe { key_bytes(out) }); if r != 0 { nvme_auth_free_key(out); return err(-r); } out
}

pub(crate) unsafe fn key_bytes(key: *mut DhchapKey) -> *mut u8 { // SAFETY: key points at a DhchapKey allocation whose flexible array starts at KEY_OFFSET.
    unsafe { key.cast::<u8>().add(KEY_OFFSET) }
}
pub(crate) fn err(errno: i32) -> *mut DhchapKey { (usize::MAX - errno as usize + 1) as *mut DhchapKey }
fn is_err(p: *mut DhchapKey) -> bool { (p as usize) >= usize::MAX - 4094 }
fn ptr_errno(p: *mut DhchapKey) -> i32 { (0usize.wrapping_sub(p as usize)) as i32 }
fn b64_decode(src: &[u8], out: &mut [u8]) -> Option<usize> { if src.len() % 4 != 0 { return None; } let mut n = 0; for q in src.chunks_exact(4) { let a = b64(q[0])?; let b = b64(q[1])?; let c = if q[2] == b'=' { 64 } else { b64(q[2])? }; let d = if q[3] == b'=' { 64 } else { b64(q[3])? }; if c == 64 && d != 64 { return None; } if n + 3 > out.len() { return None; } out[n] = (a << 2) | (b >> 4); n += 1; if c != 64 { out[n] = (b << 4) | (c >> 2); n += 1; } if d != 64 { out[n] = (c << 6) | d; n += 1; } if (c == 64 || d == 64) && q.as_ptr() != src[src.len()-4..].as_ptr() { return None; } } Some(n) }
fn b64(b: u8) -> Option<u8> { match b { b'A'..=b'Z' => Some(b - b'A'), b'a'..=b'z' => Some(b - b'a' + 26), b'0'..=b'9' => Some(b - b'0' + 52), b'+' => Some(62), b'/' => Some(63), _ => None } }

#[cfg(test)]
mod tests { use super::*; #[test] fn key_layout_and_bad_input() { let _modules = crate::test_serial::claim(); assert_eq!(KEY_OFFSET, 9); assert_eq!(nvme_auth_key_struct_size(32), 48); let p = nvme_auth_alloc_key(32, 1); assert!(!p.is_null()); nvme_auth_free_key(p); assert!(is_err(nvme_auth_extract_key(c"bad".as_ptr(), 1))); } }
