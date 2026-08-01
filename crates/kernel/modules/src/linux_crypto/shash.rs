extern crate alloc;

use alloc::boxed::Box;
use core::{mem::size_of, ptr};
use crypt::Sha256;

const LINUX_OK: i32 = 0;
const LINUX_EINVAL: i32 = 22;
const LINUX_ENOENT: i32 = 2;
const SHA256_DIGEST_SIZE: usize = 32;
const CRC_DIGEST_SIZE: usize = 4;
const CRC_FINAL_XOR: u32 = u32::MAX;
const SHASH_CTX_MAGIC: u32 = 0x4f58_5348;
const SHASH_CTX_VERSION: u32 = 1;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ShashAlg {
    Sha256,
    Crc32,
    Crc32c,
}

#[repr(C)]
pub struct CryptoShash {
    alg: ShashAlg,
}

#[repr(C)]
pub struct ShashDesc {
    tfm: *mut CryptoShash,
    flags: u32,
}

#[repr(C)]
struct ShashCtx {
    magic: u32,
    version: u32,
    alg: ShashAlg,
    sha256: Sha256,
    crc: u32,
}

/// Register Linux crypto_shash symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("crypto_alloc_shash",       crypto_alloc_shash       as *const () as usize),
        ("crypto_free_shash",        crypto_free_shash        as *const () as usize),
        ("crypto_shash_digestsize",  crypto_shash_digestsize  as *const () as usize),
        ("crypto_shash_descsize",    crypto_shash_descsize    as *const () as usize),
        ("crypto_shash_init",        crypto_shash_init        as *const () as usize),
        ("crypto_shash_update",      crypto_shash_update      as *const () as usize),
        ("crypto_shash_final",       crypto_shash_final       as *const () as usize),
        ("crypto_shash_digest",      crypto_shash_digest      as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn crypto_alloc_shash(name: *const u8, _ty: u32, _mask: u32) -> *mut CryptoShash {
    let Some(alg) = read_alg(name) else { return err_ptr(LINUX_ENOENT); };
    Box::into_raw(Box::new(CryptoShash { alg }))
}

extern "C" fn crypto_free_shash(tfm: *mut CryptoShash) {
    if tfm.is_null() || is_err(tfm) { return; }
    // SAFETY: tfm was returned by Box::into_raw in crypto_alloc_shash.
    unsafe { drop(Box::from_raw(tfm)); }
}

extern "C" fn crypto_shash_digestsize(tfm: *mut CryptoShash) -> u32 {
    alg(tfm).map(|a| digest_size(a) as u32).unwrap_or(0)
}

extern "C" fn crypto_shash_descsize(tfm: *mut CryptoShash) -> u32 {
    alg(tfm).map(|_| size_of::<ShashCtx>() as u32).unwrap_or(0)
}

extern "C" fn crypto_shash_init(desc: *mut ShashDesc) -> i32 {
    let Some(alg) = desc_alg(desc) else { return -LINUX_EINVAL; };
    let ctx = ctx_ptr(desc);
    if ctx.is_null() { return -LINUX_EINVAL; }
    let state = ShashCtx { magic: SHASH_CTX_MAGIC, version: SHASH_CTX_VERSION, alg, sha256: Sha256::new(), crc: CRC_FINAL_XOR };
    // SAFETY: caller allocated crypto_shash_descsize bytes immediately after desc.
    unsafe { ptr::write(ctx, state); }
    LINUX_OK
}

extern "C" fn crypto_shash_update(desc: *mut ShashDesc, data: *const u8, len: u32) -> i32 {
    let Some(bytes) = input(data, len as usize) else { return -LINUX_EINVAL; };
    let Some(ctx) = valid_ctx(desc) else { return -LINUX_EINVAL; };
    match ctx.alg {
        ShashAlg::Sha256 => ctx.sha256.update(bytes),
        ShashAlg::Crc32  => ctx.crc = crc::crc32_update(ctx.crc, bytes),
        ShashAlg::Crc32c => ctx.crc = crc::crc32c_update(ctx.crc, bytes),
    }
    LINUX_OK
}

extern "C" fn crypto_shash_final(desc: *mut ShashDesc, out: *mut u8) -> i32 {
    if out.is_null() { return -LINUX_EINVAL; }
    let Some(ctx) = valid_ctx(desc) else { return -LINUX_EINVAL; };
    write_digest(ctx, out)
}

extern "C" fn crypto_shash_digest(desc: *mut ShashDesc, data: *const u8, len: u32, out: *mut u8) -> i32 {
    if out.is_null() { return -LINUX_EINVAL; }
    let Some(alg) = desc_alg(desc) else { return -LINUX_EINVAL; };
    let Some(bytes) = input(data, len as usize) else { return -LINUX_EINVAL; };
    match alg {
        ShashAlg::Sha256 => {
            let digest = crypt::sha256::sha256(bytes);
            // SAFETY: out points at crypto_shash_digestsize bytes for this tfm.
            unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), out, digest.len()); }
        }
        ShashAlg::Crc32 => write_u32(out, crc::crc32_update(CRC_FINAL_XOR, bytes) ^ CRC_FINAL_XOR),
        ShashAlg::Crc32c => write_u32(out, crc::crc32c_update(CRC_FINAL_XOR, bytes) ^ CRC_FINAL_XOR),
    }
    LINUX_OK
}

fn read_alg(name: *const u8) -> Option<ShashAlg> {
    if name.is_null() { return None; }
    let mut len = 0usize;
    while len < ALG_NAME_MAX {
        // SAFETY: Linux algorithm names are NUL-terminated kernel strings.
        let b = unsafe { *name.add(len) };
        if b == 0 { break; }
        len += 1;
    }
    if len == ALG_NAME_MAX { return None; }
    // SAFETY: name points at len readable bytes before the NUL terminator.
    let bytes = unsafe { core::slice::from_raw_parts(name, len) };
    match bytes {
        b"sha256" | b"sha-256" => Some(ShashAlg::Sha256),
        b"crc32"               => Some(ShashAlg::Crc32),
        b"crc32c"              => Some(ShashAlg::Crc32c),
        _                      => None,
    }
}

const ALG_NAME_MAX: usize = 64;

fn alg(tfm: *mut CryptoShash) -> Option<ShashAlg> {
    if tfm.is_null() || is_err(tfm) { return None; }
    // SAFETY: tfm is a live CryptoShash allocated by crypto_alloc_shash.
    Some(unsafe { (*tfm).alg })
}

fn desc_alg(desc: *mut ShashDesc) -> Option<ShashAlg> {
    if desc.is_null() { return None; }
    // SAFETY: desc points at a caller-owned Linux shash_desc.
    let tfm = unsafe { (*desc).tfm };
    alg(tfm)
}

fn ctx_ptr(desc: *mut ShashDesc) -> *mut ShashCtx {
    if desc.is_null() { return core::ptr::null_mut(); }
    // SAFETY: context storage follows shash_desc per Linux shash ABI.
    unsafe { (desc as *mut u8).add(size_of::<ShashDesc>()) as *mut ShashCtx }
}

fn valid_ctx<'a>(desc: *mut ShashDesc) -> Option<&'a mut ShashCtx> {
    let p = ctx_ptr(desc);
    if p.is_null() { return None; }
    // SAFETY: context was initialized by crypto_shash_init for this desc.
    let ctx = unsafe { &mut *p };
    if ctx.magic == SHASH_CTX_MAGIC && ctx.version == SHASH_CTX_VERSION { Some(ctx) } else { None }
}

fn input<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 { return Some(&[]); }
    if data.is_null() { return None; }
    // SAFETY: caller supplies a readable kernel buffer of len bytes.
    Some(unsafe { core::slice::from_raw_parts(data, len) })
}

fn write_digest(ctx: &mut ShashCtx, out: *mut u8) -> i32 {
    match ctx.alg {
        ShashAlg::Sha256 => {
            let digest = core::mem::take(&mut ctx.sha256).finish();
            // SAFETY: out points at SHA256_DIGEST_SIZE writable bytes.
            unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), out, digest.len()); }
        }
        ShashAlg::Crc32 => write_u32(out, ctx.crc ^ CRC_FINAL_XOR),
        ShashAlg::Crc32c => write_u32(out, ctx.crc ^ CRC_FINAL_XOR),
    }
    LINUX_OK
}

fn write_u32(out: *mut u8, value: u32) {
    let bytes = value.to_be_bytes();
    // SAFETY: out points at CRC_DIGEST_SIZE writable bytes.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, CRC_DIGEST_SIZE); }
}

fn digest_size(alg: ShashAlg) -> usize {
    match alg {
        ShashAlg::Sha256 => SHA256_DIGEST_SIZE,
        ShashAlg::Crc32 | ShashAlg::Crc32c => CRC_DIGEST_SIZE,
    }
}

fn err_ptr<T>(errno: i32) -> *mut T {
    (usize::MAX - errno as usize + 1) as *mut T
}

fn is_err<T>(p: *mut T) -> bool {
    (p as usize) >= (usize::MAX - LINUX_ERR_PTR_RANGE + 1)
}

const LINUX_ERR_PTR_RANGE: usize = 4095;

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = b"123456789";
    const SHA256_ABC_PREFIX: &[u8] = &[0xba, 0x78, 0x16, 0xbf];
    const CRC32C_STANDARD: [u8; CRC_DIGEST_SIZE] = 0xE306_9283u32.to_be_bytes();

    #[repr(C)]
    struct TestDesc {
        desc: ShashDesc,
        ctx: ShashCtx,
    }

    #[test]
    fn sha256_digest_known_vector() {
        let _modules = crate::test_serial::claim();
        let tfm = crypto_alloc_shash(c"sha256".as_ptr().cast::<u8>(), 0, 0);
        assert!(!is_err(tfm));
        let mut desc = ShashDesc { tfm, flags: 0 };
        let mut out = [0u8; SHA256_DIGEST_SIZE];
        assert_eq!(crypto_shash_digest(&mut desc, b"abc".as_ptr(), b"abc".len() as u32, out.as_mut_ptr()), LINUX_OK);
        assert_eq!(&out[..SHA256_ABC_PREFIX.len()], SHA256_ABC_PREFIX);
        crypto_free_shash(tfm);
    }

    #[test]
    fn crc32c_digest_known_vector() {
        let _modules = crate::test_serial::claim();
        let tfm = crypto_alloc_shash(c"crc32c".as_ptr().cast::<u8>(), 0, 0);
        assert!(!is_err(tfm));
        let mut desc = ShashDesc { tfm, flags: 0 };
        let mut out = [0u8; CRC_DIGEST_SIZE];
        assert_eq!(crypto_shash_digest(&mut desc, DATA.as_ptr(), DATA.len() as u32, out.as_mut_ptr()), LINUX_OK);
        assert_eq!(out, CRC32C_STANDARD);
        crypto_free_shash(tfm);
    }

    #[test]
    fn streaming_sha256_matches_digest() {
        let _modules = crate::test_serial::claim();
        let tfm = crypto_alloc_shash(c"sha256".as_ptr().cast::<u8>(), 0, 0);
        let mut desc = TestDesc {
            desc: ShashDesc { tfm, flags: 0 },
            ctx: ShashCtx { magic: 0, version: 0, alg: ShashAlg::Sha256, sha256: Sha256::new(), crc: 0 },
        };
        let mut out = [0u8; SHA256_DIGEST_SIZE];
        assert_eq!(crypto_shash_init(&mut desc.desc), LINUX_OK);
        assert_eq!(crypto_shash_update(&mut desc.desc, b"abc".as_ptr(), b"abc".len() as u32), LINUX_OK);
        assert_eq!(crypto_shash_final(&mut desc.desc, out.as_mut_ptr()), LINUX_OK);
        assert_eq!(&out[..SHA256_ABC_PREFIX.len()], SHA256_ABC_PREFIX);
        crypto_free_shash(tfm);
    }

    #[test]
    fn unknown_algorithm_returns_error_pointer() {
        let _modules = crate::test_serial::claim();
        let tfm = crypto_alloc_shash(c"md5".as_ptr().cast::<u8>(), 0, 0);
        assert!(is_err(tfm));
    }
}
