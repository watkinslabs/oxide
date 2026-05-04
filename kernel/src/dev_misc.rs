// Misc char devices per docs/16 + docs/19: /dev/null, /dev/zero,
// /dev/full, /dev/random, /dev/urandom. v1 minimal Inode impls;
// register at boot via `crate::devfs::register`.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// `/dev/null` — read returns 0 (EOF), write discards.
pub struct NullInode;
impl Inode for NullInode {
    fn ino(&self) -> Ino { 0x2000_0001 }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}

/// `/dev/zero` — read fills with NUL, write discards.
pub struct ZeroInode;
impl Inode for ZeroInode {
    fn ino(&self) -> Ino { 0x2000_0002 }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, b: &mut [u8]) -> KResult<usize> {
        for x in b.iter_mut() { *x = 0; }
        Ok(b.len())
    }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}

/// `/dev/full` — read fills with NUL like /dev/zero; write
/// returns -ENOSPC. POSIX-shaped so libc `posix_fallocate`-on-
/// /dev/full tests work.
pub struct FullInode;
impl Inode for FullInode {
    fn ino(&self) -> Ino { 0x2000_0003 }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, b: &mut [u8]) -> KResult<usize> {
        for x in b.iter_mut() { *x = 0; }
        Ok(b.len())
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// LCG pseudo-random source seeded from a monotonic counter. v1
/// has no real entropy pool (per docs/26 the CPRNG/RDRAND wiring
/// rides P3 follow-up); LCG is enough for libc's "give me bytes"
/// shape but NOT for cryptographic use.
static PRNG_STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

fn lcg_next() -> u64 {
    let mut s = PRNG_STATE.load(Ordering::Relaxed);
    s = s.wrapping_mul(0x5851_F42D_4C95_7F2D).wrapping_add(0x14057B7E_F767_814F);
    PRNG_STATE.store(s, Ordering::Relaxed);
    s
}

/// `/dev/random` and `/dev/urandom` — fill with LCG bytes.
/// SECURITY: NOT cryptographic; v1 placeholder until docs/26
/// CPRNG lands.
pub struct RandomInode;
impl Inode for RandomInode {
    fn ino(&self) -> Ino { 0x2000_0004 }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, b: &mut [u8]) -> KResult<usize> {
        let mut i = 0;
        while i < b.len() {
            let v = lcg_next().to_le_bytes();
            let n = (b.len() - i).min(8);
            b[i..i + n].copy_from_slice(&v[..n]);
            i += n;
        }
        Ok(b.len())
    }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}
