use alloc::vec::Vec;
use core::ffi::c_char;
#[cfg(test)] use core::ptr;
use super::hmac::{cstr, hash_len, hmac_once, slice, EINVAL, FABRICS_LABEL, NVME_AUTH_HASH_SHA512};

const ENOMEM: i32 = 12;
const MAX_DIGEST: usize = 64;

/// Register generated-PSK, identity digest and TLS PSK derivation symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("nvme_auth_generate_psk", nvme_auth_generate_psk as *const () as usize),
        ("nvme_auth_generate_digest", nvme_auth_generate_digest as *const () as usize),
        ("nvme_auth_derive_tls_psk", nvme_auth_derive_tls_psk as *const () as usize),
    ] { export(name, addr, true); }
}

extern "C" fn nvme_auth_generate_psk(id: u8, skey: *const u8, skey_len: usize, c1: *const u8, c2: *const u8, hash_len_arg: usize, ret: *mut *mut u8, ret_len: *mut usize) -> i32 {
    if ret.is_null() || ret_len.is_null() || c1.is_null() || c2.is_null() { return -EINVAL; }
    let n = hash_len(id); if n == 0 || hash_len_arg != n { return -EINVAL; }
    let (Some(skey), Some(c1), Some(c2)) = (slice(skey, skey_len), slice(c1, n), slice(c2, n)) else { return -EINVAL; };
    let out = crate::linux_alloc::alloc_bytes(n, core::mem::align_of::<usize>(), true); if out.is_null() { return -ENOMEM; }
    let mut data = [0u8; MAX_DIGEST * 2]; data[..n].copy_from_slice(c1); data[n..n * 2].copy_from_slice(c2);
    let r = hmac_once(id, Some(skey), Some(&data[..n * 2]), out); if r != 0 { crate::linux_alloc::kfree(out); return r; }
    // SAFETY: ret and ret_len were validated writable by the kernel ABI caller.
    unsafe { *ret = out; *ret_len = n; } 0
}
extern "C" fn nvme_auth_generate_digest(id: u8, psk: *const u8, psk_len: usize, subsys: *const c_char, host: *const c_char, ret: *mut *mut c_char) -> i32 {
    if ret.is_null() || id == NVME_AUTH_HASH_SHA512 { return -EINVAL; } let n = hash_len(id); if n == 0 { return -EINVAL; }
    let (Some(psk), Some(subsys), Some(host)) = (slice(psk, psk_len), cstr(subsys), cstr(host)) else { return -EINVAL; };
    let mut msg = Vec::with_capacity(host.len() + subsys.len() + FABRICS_LABEL.len() + 2); msg.extend_from_slice(host); msg.push(b' '); msg.extend_from_slice(subsys); msg.push(b' '); msg.extend_from_slice(FABRICS_LABEL);
    let mut digest = [0u8; MAX_DIGEST]; let r = hmac_once(id, Some(psk), Some(&msg), digest.as_mut_ptr()); if r != 0 { return r; }
    let enc_len = if n == 32 { 44 } else { 64 }; let out = crate::linux_alloc::alloc_bytes(enc_len + 1, core::mem::align_of::<usize>(), true); if out.is_null() { return -ENOMEM; }
    // SAFETY: output has enc_len + NUL bytes and source contains n bytes.
    unsafe { b64_encode(&digest[..n], core::slice::from_raw_parts_mut(out, enc_len)); *out.add(enc_len) = 0; *ret = out.cast(); } 0
}
extern "C" fn nvme_auth_derive_tls_psk(id: i32, psk: *const u8, psk_len: usize, digest: *const c_char, ret: *mut *mut u8) -> i32 {
    if ret.is_null() || id < 0 { return -EINVAL; } let id = id as u8; if id == NVME_AUTH_HASH_SHA512 { return -EINVAL; } let n = hash_len(id); if n == 0 || psk_len != n { return -EINVAL; }
    let (Some(psk), Some(digest)) = (slice(psk, psk_len), cstr(digest)) else { return -EINVAL; };
    let zero = [0u8; MAX_DIGEST]; let mut prk = [0u8; MAX_DIGEST]; let r = hmac_once(id, Some(&zero[..n]), Some(psk), prk.as_mut_ptr()); if r != 0 { return r; }
    let mut info = Vec::with_capacity(2 + 1 + 18 + 1 + 3 + 1 + digest.len() + 1); info.extend_from_slice(&(n as u16).to_be_bytes()); info.push(18); info.extend_from_slice(b"tls13 nvme-tls-psk"); let mut context = [0u8; 4]; context[0] = b'0' + (id / 10); context[1] = b'0' + (id % 10); context[2] = b' '; let ctx = &context[..3]; if ctx.len() + digest.len() > u8::MAX as usize { return -EINVAL; } info.push((ctx.len() + digest.len()) as u8); info.extend_from_slice(ctx); info.extend_from_slice(digest); info.push(1);
    let out = crate::linux_alloc::alloc_bytes(n, core::mem::align_of::<usize>(), true); if out.is_null() { return -ENOMEM; } let r = hmac_once(id, Some(&prk[..n]), Some(&info), out); prk.fill(0); if r != 0 { crate::linux_alloc::kfree(out); return r; } // SAFETY: ret was checked non-null and receives the owned result.
    unsafe { *ret = out; } 0
}
fn b64_encode(input: &[u8], out: &mut [u8]) { const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; let mut i = 0; let mut o = 0; while i + 3 <= input.len() { let x = u32::from_be_bytes([0, input[i], input[i + 1], input[i + 2]]); out[o] = TABLE[((x >> 18) & 63) as usize]; out[o + 1] = TABLE[((x >> 12) & 63) as usize]; out[o + 2] = TABLE[((x >> 6) & 63) as usize]; out[o + 3] = TABLE[(x & 63) as usize]; i += 3; o += 4; } match input.len() - i { 1 => { let x = (input[i] as u32) << 16; out[o] = TABLE[((x >> 18) & 63) as usize]; out[o + 1] = TABLE[((x >> 12) & 63) as usize]; out[o + 2] = b'='; out[o + 3] = b'='; }, 2 => { let x = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8); out[o] = TABLE[((x >> 18) & 63) as usize]; out[o + 1] = TABLE[((x >> 12) & 63) as usize]; out[o + 2] = TABLE[((x >> 6) & 63) as usize]; out[o + 3] = b'='; }, _ => {} } }

#[cfg(test)]
mod tests { use super::*;
// SAFETY: p/tls were just returned non-null by generate_psk/derive_tls_psk with hash_len(1)==32 bytes allocated, so reading the first 4 bytes back is in-bounds.
#[test] fn psk_tls_vectors_sha256() { let _modules = crate::test_serial::claim(); let skey: [u8; 32] = core::array::from_fn(|i| b'A' + i as u8); let c1: [u8; 32] = core::array::from_fn(|i| i as u8); let c2: [u8; 32] = core::array::from_fn(|i| 0xff - i as u8); let mut p = ptr::null_mut(); let mut n = 0; assert_eq!(nvme_auth_generate_psk(1, skey.as_ptr(), 32, c1.as_ptr(), c2.as_ptr(), 32, &mut p, &mut n), 0); assert_eq!(unsafe { core::slice::from_raw_parts(p, 4) }, &[0x17, 0x33, 0xc5, 0x9f]); let mut d = ptr::null_mut(); assert_eq!(nvme_auth_generate_digest(1, p, n, c"subsysnqn".as_ptr(), c"hostnqn".as_ptr(), &mut d), 0); assert_eq!(super::super::hmac::cstr(d).unwrap(), b"OldoKuTfKddMuyCznAZojkWD7P4D9/AtzDzLimtOxqI="); let mut tls = ptr::null_mut(); assert_eq!(nvme_auth_derive_tls_psk(1, p, n, d, &mut tls), 0); assert_eq!(unsafe { core::slice::from_raw_parts(tls, 4) }, &[0x3c, 0x17, 0xda, 0x62]); crate::linux_alloc::kfree(p); crate::linux_alloc::kfree(d.cast()); crate::linux_alloc::kfree(tls); }
// SAFETY: p was just returned non-null by generate_psk with hash_len(2)==48 bytes allocated, so reading the first 4 bytes back is in-bounds.
#[test] fn psk_digest_vector_sha384() { let _modules = crate::test_serial::claim(); let skey: [u8; 48] = core::array::from_fn(|i| b'A' + i as u8); let c1: [u8; 48] = core::array::from_fn(|i| i as u8); let c2: [u8; 48] = core::array::from_fn(|i| 0xff - i as u8); let mut p = ptr::null_mut(); let mut n = 0; assert_eq!(nvme_auth_generate_psk(2, skey.as_ptr(), 48, c1.as_ptr(), c2.as_ptr(), 48, &mut p, &mut n), 0); assert_eq!(unsafe { core::slice::from_raw_parts(p, 4) }, &[0xf1, 0x4b, 0x2d, 0xd3]); let mut d = ptr::null_mut(); assert_eq!(nvme_auth_generate_digest(2, p, n, c"subsysnqn".as_ptr(), c"hostnqn".as_ptr(), &mut d), 0); assert_eq!(super::super::hmac::cstr(d).unwrap(), b"cffMWk8TSS7HOQebjgYEIkrPrjWPV4JE5cdPB8WhEvY4JBW5YynKyv66XscN4A9n"); crate::linux_alloc::kfree(p); crate::linux_alloc::kfree(d.cast()); } }
