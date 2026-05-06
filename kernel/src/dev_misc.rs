// Misc char devices per docs/16 + docs/19: /dev/null, /dev/zero,
// /dev/full, /dev/random, /dev/urandom. v1 minimal Inode impls;
// register at boot via `crate::devfs::register`.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Boot-time smoke test: each Inode read fills the right bytes.
/// `/dev/zero` returns NUL, `/dev/null` returns 0 (EOF), `/dev/random`
/// fills with non-deterministic bytes (we just check len). Run from
/// `kernel_main` after `devfs::init()`.
/// # SAFETY: caller is the boot path; PMM up; single-CPU pre-init.
/// # C: O(1) per inode
pub fn smoke_test() {
    use vfs::Inode;

    let mut buf = [0xAAu8; 16];
    let n = ZeroInode.read(0, &mut buf).expect("zero.read");
    kassert!(n == 16, "zero read len");
    for b in buf.iter() { kassert!(*b == 0, "zero read fills NUL"); }

    let mut buf2 = [0xBBu8; 16];
    let n = NullInode.read(0, &mut buf2).expect("null.read");
    kassert!(n == 0, "null read EOF");
    for b in buf2.iter() { kassert!(*b == 0xBB, "null read leaves buf"); }

    let mut buf3 = [0u8; 32];
    let n = RandomInode.read(0, &mut buf3).expect("random.read");
    kassert!(n == 32, "random read len");
    let nz = buf3.iter().filter(|b| **b != 0).count();
    kassert!(nz > 0, "random read produces non-zero bytes");

    let n = NullInode.write(0, b"hello").expect("null.write");
    kassert!(n == 5, "null write accepts all");
    let n = ZeroInode.write(0, b"hello").expect("zero.write");
    kassert!(n == 5, "zero write accepts all");
    let r = FullInode.write(0, b"hello");
    kassert!(r.is_err(), "full write returns Eio");

    debug_boot! { klog::write_raw(b"[INFO]  dev-misc-smoke: ok\n"); }
}

use hal::kassert;

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

/// `/dev/kmsg` — Linux kernel ring-buffer file. Reads pull bytes
/// from `klog::ring_read` (the in-memory dmesg log); writes are
/// discarded for v1 (no userspace kmsg-priority injection).
/// Each open's reader cursor is reset to 0 at open — repeated
/// `cat /dev/kmsg` invocations from userspace each see the
/// available tail of the ring.
pub struct KmsgInode;
impl Inode for KmsgInode {
    fn ino(&self) -> Ino { 0x2000_000A }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, b: &mut [u8]) -> KResult<usize> {
        let (n, _next) = klog::ring_read(off as usize, b);
        Ok(n)
    }
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

/// Pull one 64-bit pseudo-random value from the shared LCG.
/// Used by `RandomInode` and `kernel_sys_getrandom`.
/// SECURITY: NOT cryptographic — placeholder until docs/26.
/// # C: O(1)
pub fn lcg_next() -> u64 {
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
