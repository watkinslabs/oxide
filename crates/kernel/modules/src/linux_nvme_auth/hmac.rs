use alloc::boxed::Box;
use core::ffi::c_char;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use crypt::{Sha256, Sha512};

pub const NVME_AUTH_HASH_SHA256: u8 = 1;
pub const NVME_AUTH_HASH_SHA384: u8 = 2;
pub const NVME_AUTH_HASH_SHA512: u8 = 3;
pub const NVME_AUTH_HASH_INVALID: u8 = u8::MAX;
pub const NVME_AUTH_DHGROUP_NULL: u8 = 0;
pub const NVME_AUTH_DHGROUP_INVALID: u8 = u8::MAX;
pub const EINVAL: i32 = 22;
const HMAC_CTX_SIZE: usize = 280;
const CSTR_MAX: usize = 4096;
pub(crate) const FABRICS_LABEL: &[u8] = b"NVMe-over-Fabrics";
const SHA384_IV: [u64; 8] = [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4];
static SEQNUM: AtomicU32 = AtomicU32::new(0);
static DH_NAMES: [&[u8]; 6] = [b"null\0", b"ffdhe2048\0", b"ffdhe3072\0", b"ffdhe4096\0", b"ffdhe6144\0", b"ffdhe8192\0"];
static DH_KPPS: [&[u8]; 6] = [b"null\0", b"ffdhe2048(dh)\0", b"ffdhe3072(dh)\0", b"ffdhe4096(dh)\0", b"ffdhe6144(dh)\0", b"ffdhe8192(dh)\0"];
static HMAC_NAMES: [&[u8]; 4] = [b"\0", b"hmac(sha256)\0", b"hmac(sha384)\0", b"hmac(sha512)\0"];
static DIGEST_NAMES: [&[u8]; 4] = [b"\0", b"sha256\0", b"sha384\0", b"sha512\0"];

#[repr(C)]
struct AuthHmacCtx { hmac_id: u8, _pad: [u8; 7], state: *mut HmacState, _tail: [u8; HMAC_CTX_SIZE - 16] }

enum HmacState { S256 { inner: Sha256, opad: [u8; 64] }, S384 { inner: Sha512, opad: [u8; 128] }, S512 { inner: Sha512, opad: [u8; 128] } }

/// Register DHCHAP mappings, sequence and HMAC API symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("nvme_auth_get_seqnum", nvme_auth_get_seqnum as *const () as usize),
        ("nvme_auth_dhgroup_name", nvme_auth_dhgroup_name as *const () as usize),
        ("nvme_auth_dhgroup_kpp", nvme_auth_dhgroup_kpp as *const () as usize),
        ("nvme_auth_dhgroup_id", nvme_auth_dhgroup_id as *const () as usize),
        ("nvme_auth_hmac_name", nvme_auth_hmac_name as *const () as usize),
        ("nvme_auth_digest_name", nvme_auth_digest_name as *const () as usize),
        ("nvme_auth_hmac_id", nvme_auth_hmac_id as *const () as usize),
        ("nvme_auth_hmac_hash_len", nvme_auth_hmac_hash_len as *const () as usize),
        ("nvme_auth_hmac_init", nvme_auth_hmac_init as *const () as usize),
        ("nvme_auth_hmac_update", nvme_auth_hmac_update as *const () as usize),
        ("nvme_auth_hmac_final", nvme_auth_hmac_final as *const () as usize),
        ("nvme_auth_augmented_challenge", nvme_auth_augmented_challenge as *const () as usize),
    ] { export(name, addr, true); }
}

extern "C" fn nvme_auth_get_seqnum() -> u32 {
    loop {
        let old = SEQNUM.load(Ordering::Acquire);
        let next = if old == 0 { random_u32() } else { old.wrapping_add(1).max(1) };
        if SEQNUM.compare_exchange(old, next, Ordering::AcqRel, Ordering::Acquire).is_ok() { return next; }
    }
}

extern "C" fn nvme_auth_dhgroup_name(id: u8) -> *const c_char { DH_NAMES.get(id as usize).map_or(ptr::null(), |x| x.as_ptr().cast()) }
extern "C" fn nvme_auth_dhgroup_kpp(id: u8) -> *const c_char { DH_KPPS.get(id as usize).map_or(ptr::null(), |x| x.as_ptr().cast()) }
extern "C" fn nvme_auth_dhgroup_id(name: *const c_char) -> u8 { map_id(name, &DH_NAMES).unwrap_or(NVME_AUTH_DHGROUP_INVALID) }
extern "C" fn nvme_auth_hmac_name(id: u8) -> *const c_char { HMAC_NAMES.get(id as usize).filter(|x| x.len() > 1).map_or(ptr::null(), |x| x.as_ptr().cast()) }
extern "C" fn nvme_auth_digest_name(id: u8) -> *const c_char { DIGEST_NAMES.get(id as usize).filter(|x| x.len() > 1).map_or(ptr::null(), |x| x.as_ptr().cast()) }
extern "C" fn nvme_auth_hmac_id(name: *const c_char) -> u8 { map_id(name, &HMAC_NAMES).unwrap_or(NVME_AUTH_HASH_INVALID) }
extern "C" fn nvme_auth_hmac_hash_len(id: u8) -> usize { hash_len(id) }

extern "C" fn nvme_auth_hmac_init(ctx: *mut AuthHmacCtx, id: u8, key: *const u8, key_len: usize) -> i32 {
    if ctx.is_null() || slice(key, key_len).is_none() || hash_len(id) == 0 { return -EINVAL; }
    // SAFETY: ctx is a caller-owned ABI context with the declared fixed layout.
    unsafe { ptr::write_bytes(ctx.cast::<u8>(), 0, HMAC_CTX_SIZE); let state = make_hmac(id, slice(key, key_len).unwrap()); (*ctx).hmac_id = id; (*ctx).state = Box::into_raw(Box::new(state)); }
    0
}
extern "C" fn nvme_auth_hmac_update(ctx: *mut AuthHmacCtx, data: *const u8, len: usize) {
    let Some(data) = slice(data, len) else { return; };
    // SAFETY: state is installed by nvme_auth_hmac_init and remains live until final.
    unsafe { if !ctx.is_null() && !(*ctx).state.is_null() { update(&mut *(*ctx).state, data); } }
}
extern "C" fn nvme_auth_hmac_final(ctx: *mut AuthHmacCtx, out: *mut u8) {
    if ctx.is_null() || out.is_null() { return; }
    // SAFETY: context owns the state allocated by init and out provides its algorithm digest width.
    unsafe { let state = (*ctx).state; if state.is_null() { return; } let digest = finish(Box::from_raw(state)); ptr::copy_nonoverlapping(digest.as_ptr(), out, digest.len()); ptr::write_bytes(ctx.cast::<u8>(), 0, HMAC_CTX_SIZE); }
}
extern "C" fn nvme_auth_augmented_challenge(id: u8, skey: *const u8, skey_len: usize, challenge: *const u8, aug: *mut u8, hlen: usize) -> i32 {
    if aug.is_null() || hash_len(id) != hlen { return -EINVAL; }
    hmac_once(id, slice(skey, skey_len), slice(challenge, hlen), aug)
}

pub(crate) fn hmac_once(id: u8, key: Option<&[u8]>, data: Option<&[u8]>, out: *mut u8) -> i32 {
    if out.is_null() || hash_len(id) == 0 { return -EINVAL; }
    let (Some(key), Some(data)) = (key, data) else { return -EINVAL; };
    let mut state = make_hmac(id, key); update(&mut state, data); let digest = finish(Box::new(state));
    // SAFETY: caller supplies hash_len(id) writable output bytes.
    unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), out, digest.len()); }
    0
}
pub(crate) fn hash_len(id: u8) -> usize { match id { NVME_AUTH_HASH_SHA256 => 32, NVME_AUTH_HASH_SHA384 => 48, NVME_AUTH_HASH_SHA512 => 64, _ => 0 } }
pub(crate) fn cstr(p: *const c_char) -> Option<&'static [u8]> { if p.is_null() { return None; } let mut n = 0; while n < CSTR_MAX { // SAFETY: callers pass a NUL-terminated kernel string.
    if unsafe { *p.add(n) } == 0 { return Some(unsafe { core::slice::from_raw_parts(p.cast(), n) }); } n += 1; } None }
pub(crate) fn slice<'a>(p: *const u8, n: usize) -> Option<&'a [u8]> { if n == 0 { Some(&[]) } else if p.is_null() { None } else { Some(unsafe { core::slice::from_raw_parts(p, n) }) } }

fn map_id(name: *const c_char, names: &[&[u8]]) -> Option<u8> { let got = cstr(name)?; names.iter().position(|v| v.len() > 1 && got.starts_with(&v[..v.len() - 1])).map(|i| i as u8) }
fn random_u32() -> u32 { let mut b = [0u8; 4]; devfs::misc::random_fill(&mut b); u32::from_le_bytes(b) }
fn make_hmac(id: u8, key: &[u8]) -> HmacState { match id { NVME_AUTH_HASH_SHA256 => { let (ipad, opad) = pads256(key); let mut inner = Sha256::new(); inner.update(&ipad); HmacState::S256 { inner, opad } }, NVME_AUTH_HASH_SHA384 => { let (ipad, opad) = pads512(key, true); let mut inner = Sha512::with_iv(SHA384_IV); inner.update(&ipad); HmacState::S384 { inner, opad } }, _ => { let (ipad, opad) = pads512(key, false); let mut inner = Sha512::new(); inner.update(&ipad); HmacState::S512 { inner, opad } } } }
fn pads256(key: &[u8]) -> ([u8; 64], [u8; 64]) { let mut k = [0u8; 64]; if key.len() > k.len() { k[..32].copy_from_slice(&digest256(key)); } else { k[..key.len()].copy_from_slice(key); } let mut i = [0u8; 64]; let mut o = [0u8; 64]; for n in 0..64 { i[n] = k[n] ^ 0x36; o[n] = k[n] ^ 0x5c; } (i, o) }
fn pads512(key: &[u8], short: bool) -> ([u8; 128], [u8; 128]) { let mut k = [0u8; 128]; if key.len() > k.len() { let d = digest512(key, short); k[..d.len()].copy_from_slice(&d); } else { k[..key.len()].copy_from_slice(key); } let mut i = [0u8; 128]; let mut o = [0u8; 128]; for n in 0..128 { i[n] = k[n] ^ 0x36; o[n] = k[n] ^ 0x5c; } (i, o) }
fn update(s: &mut HmacState, data: &[u8]) { match s { HmacState::S256 { inner, .. } => inner.update(data), HmacState::S384 { inner, .. } | HmacState::S512 { inner, .. } => inner.update(data) } }
fn finish(s: Box<HmacState>) -> alloc::vec::Vec<u8> { match *s { HmacState::S256 { inner, opad } => { let d = inner.finish(); let mut out = Sha256::new(); out.update(&opad); out.update(&d); out.finish().to_vec() }, HmacState::S384 { inner, opad } => { let d = inner.finish(); let mut out = Sha512::with_iv(SHA384_IV); out.update(&opad); out.update(&d[..48]); out.finish()[..48].to_vec() }, HmacState::S512 { inner, opad } => { let d = inner.finish(); let mut out = Sha512::new(); out.update(&opad); out.update(&d); out.finish().to_vec() } } }
fn digest256(data: &[u8]) -> [u8; 32] { let mut h = Sha256::new(); h.update(data); h.finish() }
fn digest512(data: &[u8], short: bool) -> alloc::vec::Vec<u8> { let mut h = if short { Sha512::with_iv(SHA384_IV) } else { Sha512::new() }; h.update(data); let d = h.finish(); if short { d[..48].to_vec() } else { d.to_vec() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn maps_and_hmac_context_work() { let _modules = crate::test_serial::claim(); assert_eq!(nvme_auth_dhgroup_id(c"ffdhe3072".as_ptr()), 2); assert_eq!(nvme_auth_hmac_hash_len(3), 64); let mut ctx: AuthHmacCtx = unsafe { core::mem::zeroed() }; let mut out = [0u8; 32]; assert_eq!(nvme_auth_hmac_init(&mut ctx, 1, b"key".as_ptr(), 3), 0); nvme_auth_hmac_update(&mut ctx, b"The quick brown fox jumps over the lazy dog".as_ptr(), 43); nvme_auth_hmac_final(&mut ctx, out.as_mut_ptr()); assert_eq!(&out[..4], &[0xf7, 0xbc, 0x83, 0xf4]); }
    #[test] fn invalid_inputs_are_rejected() { let _modules = crate::test_serial::claim(); assert_eq!(nvme_auth_hmac_id(ptr::null()), NVME_AUTH_HASH_INVALID); assert_eq!(nvme_auth_dhgroup_id(ptr::null()), NVME_AUTH_DHGROUP_INVALID); }
}
