// Misc char devices per docs/16 + docs/19: /dev/null, /dev/zero,
// /dev/full, /dev/random, /dev/urandom. v1 minimal Inode impls;
// register at boot via `crate::register`.


use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Boot-time smoke test: each Inode read fills the right bytes.
/// `/dev/zero` returns NUL, `/dev/null` returns 0 (EOF), `/dev/random`
/// fills with non-deterministic bytes (we just check len). Run from
/// `kernel_main` after `crate::init()`.
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

    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  dev-misc-smoke: ok\n");
    }
}

use hal::kassert;

/// `/dev/null` — read returns 0 (EOF), write discards.
pub struct NullInode;
impl Inode for NullInode {
    fn ino(&self) -> Ino { 0x2000_0001 }
    fn fsid(&self) -> u64 { crate::DEVFS_FSID }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn rdev(&self) -> u32 { 0x0103 }               // 1:3 mem/null
    fn perm(&self) -> Option<u16> { Some(0o666) }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}

/// Static symlink with a fixed target — backs the standard `/dev`
/// links `stdin`/`stdout`/`stderr`/`fd` that every Linux system
/// carries (→ `/proc/self/fd/*`). Shells (`< /dev/stdin`,
/// `> /dev/stdout`), bash process substitution (`/dev/fd/<n>`), and
/// scripts depend on them.
pub struct SymlinkInode {
    pub target: &'static [u8],
    pub ino:    Ino,
}
impl Inode for SymlinkInode {
    fn ino(&self) -> Ino { self.ino }
    fn fsid(&self) -> u64 { crate::DEVFS_FSID }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<alloc::vec::Vec<u8>> { Ok(self.target.to_vec()) }
}

/// `/dev/kmsg` — Linux kernel ring-buffer file. Reads pull bytes from
/// `klog::ring_read` (the in-memory dmesg log); writes inject a userspace
/// record into the ring + console (early systemd / `logger` / journald).
/// Each open's reader cursor is reset to 0 at open — repeated
/// `cat /dev/kmsg` invocations from userspace each see the
/// available tail of the ring.
pub struct KmsgInode;
impl Inode for KmsgInode {
    fn ino(&self) -> Ino { 0x2000_000A }
    fn fsid(&self) -> u64 { crate::DEVFS_FSID }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn rdev(&self) -> u32 { 0x010b }               // 1:11 mem/kmsg
    fn perm(&self) -> Option<u16> { Some(0o644) }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, b: &mut [u8]) -> KResult<usize> {
        let (n, _next) = klog::ring_read(off as usize, b);
        Ok(n)
    }
    /// `/dev/kmsg` is always writable; POLL_IN only when the reader's cursor
    /// (`File::pos`) is behind the ring head (unread messages). Without this,
    /// the default always-`POLL_IN` poll() busy-looped journald's epoll on
    /// /dev/kmsg ("Looping too fast"). # C: O(1)
    fn poll_file(&self, pos: u64) -> u32 {
        let mut mask = vfs::POLL_OUT;
        if (pos as usize) < klog::ring_total() { mask |= vfs::POLL_IN; }
        mask
    }
    /// `/dev/kmsg` write injects the message into the kernel log ring (the
    /// kmsg contract: early systemd + userspace `logger`/journald-forward
    /// write here, then it shows in `dmesg`/console). An optional leading
    /// `<N>` syslog-priority prefix is stripped; a trailing newline is
    /// ensured so each write is one record. Before this, writes were
    /// silently discarded.
    /// # C: O(len)
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> {
        let mut msg = b;
        if msg.first() == Some(&b'<') {
            if let Some(gt) = msg.iter().take(6).position(|&c| c == b'>') {
                if gt > 1 && msg[1..gt].iter().all(|c| c.is_ascii_digit()) {
                    msg = &msg[gt + 1..];
                }
            }
        }
        klog::kmsg_write(msg);
        if msg.last() != Some(&b'\n') { klog::kmsg_write(b"\n"); }
        Ok(b.len())
    }
}

/// `/dev/zero` — read fills with NUL, write discards.
pub struct ZeroInode;
impl Inode for ZeroInode {
    fn ino(&self) -> Ino { 0x2000_0002 }
    fn fsid(&self) -> u64 { crate::DEVFS_FSID }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn rdev(&self) -> u32 { 0x0105 }               // 1:5 mem/zero
    fn perm(&self) -> Option<u16> { Some(0o666) }
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
    fn fsid(&self) -> u64 { crate::DEVFS_FSID }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn rdev(&self) -> u32 { 0x0107 }               // 1:7 mem/full
    fn perm(&self) -> Option<u16> { Some(0o666) }
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

/// Mix externally-sourced entropy bytes into the shared PRNG state.
/// Folds each byte into `PRNG_STATE` via a wrapping multiply-xor so real
/// hardware entropy (e.g. virtio-rng at boot, `/dev/hwrng` reads) actually
/// perturbs the stream the LCG produces. NOT a cryptographic mixer — it is
/// a deterministic avalanche over the existing non-crypto LCG placeholder
/// (docs/26 CPRNG supersedes). Empty input is a no-op.
/// # C: O(bytes.len())
pub fn add_entropy(bytes: &[u8]) {
    if bytes.is_empty() { return; }
    let mut s = PRNG_STATE.load(Ordering::Relaxed);
    for &b in bytes {
        // Fold the byte in, then avalanche so adjacent inputs diverge.
        s = (s ^ (b as u64)).wrapping_mul(0x100000001B3);
        s ^= s >> 29;
    }
    PRNG_STATE.store(s, Ordering::Relaxed);
}

/// Pull one 64-bit pseudo-random value from the shared LCG.
/// Used by `RandomInode` and `sys_getrandom`.
/// SECURITY: NOT cryptographic — placeholder until docs/26.
/// # C: O(1)
pub fn lcg_next() -> u64 {
    let mut s = PRNG_STATE.load(Ordering::Relaxed);
    s = s.wrapping_mul(0x5851_F42D_4C95_7F2D).wrapping_add(0x14057B7E_F767_814F);
    PRNG_STATE.store(s, Ordering::Relaxed);
    s
}

/// Hardware-entropy source hook. `/dev/hwrng` reads route here; the kmain
/// boot path installs the virtio-rng `fill` fn after PCI enumeration via
/// `set_hwrng_source`. Stored as a raw fn pointer so devfs needn't depend
/// on the driver crate (same pattern as the dir-overlay hook). 0 = absent.
static HWRNG_SOURCE: AtomicU64 = AtomicU64::new(0);
type HwRngFn = fn(&mut [u8]) -> usize;

/// Install the hardware-entropy source (virtio-rng `fill`). Boot, once,
/// only when a virtio-rng device is present. Until installed, `/dev/hwrng`
/// reads return 0 (EOF) rather than fabricating bytes.
/// # C: O(1)
pub fn set_hwrng_source(f: HwRngFn) {
    HWRNG_SOURCE.store(f as usize as u64, Ordering::Release);
}

/// `/dev/hwrng` — Linux hardware-RNG char device. Each read pulls fresh
/// bytes from the installed virtio-rng source; with no source installed
/// (no device) reads return 0 (EOF), matching a `/dev/hwrng` whose backing
/// hwrng has no current_rng. Real hardware entropy, NOT the LCG.
pub struct HwRngInode;
impl Inode for HwRngInode {
    fn ino(&self) -> Ino { 0x2000_0005 }
    fn fsid(&self) -> u64 { crate::DEVFS_FSID }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn rdev(&self) -> u32 { 0x0ab7 }               // 10:183 misc/hw_random
    fn perm(&self) -> Option<u16> { Some(0o644) }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, b: &mut [u8]) -> KResult<usize> {
        let p = HWRNG_SOURCE.load(Ordering::Acquire);
        if p == 0 { return Ok(0); }
        // SAFETY: p was stored from a `HwRngFn` via set_hwrng_source; the
        // function pointer ABI matches and it is only ever set to the
        // virtio-rng `fill` entry, which reads device entropy into `b`.
        let f: HwRngFn = unsafe { core::mem::transmute(p as usize) };
        Ok(f(b))
    }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}

/// `/dev/autofs` — misc char device for the built-in autofs control ABI.
pub struct AutofsInode;
impl Inode for AutofsInode {
    fn ino(&self) -> Ino { 0x2000_0006 }
    fn fsid(&self) -> u64 { crate::DEVFS_FSID }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn rdev(&self) -> u32 { 0x0aec }               // 10:236 misc/autofs
    fn perm(&self) -> Option<u16> { Some(0o600) }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// `/dev/random` and `/dev/urandom` — fill with LCG bytes.
/// SECURITY: NOT cryptographic; v1 placeholder until docs/26
/// CPRNG lands.
pub struct RandomInode;
impl Inode for RandomInode {
    fn ino(&self) -> Ino { 0x2000_0004 }
    fn fsid(&self) -> u64 { crate::DEVFS_FSID }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn rdev(&self) -> u32 { 0x0108 }               // 1:8 mem/random
    fn perm(&self) -> Option<u16> { Some(0o666) }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Mixing entropy must perturb the PRNG state: the LCG stream after a
    /// mix differs from the stream without it.
    #[test]
    fn add_entropy_changes_state() {
        let before = lcg_next();
        add_entropy(&[0x42, 0x99, 0x01, 0xFE]);
        let after = lcg_next();
        assert_ne!(before, after, "entropy mix must perturb the stream");
    }

    /// Different entropy inputs must drive the state to different places.
    #[test]
    fn distinct_inputs_distinct_state() {
        add_entropy(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let a = lcg_next();
        add_entropy(&[8, 7, 6, 5, 4, 3, 2, 1]);
        let b = lcg_next();
        assert_ne!(a, b, "distinct entropy inputs must diverge");
    }

    /// Empty input is a no-op: the stream is unchanged.
    #[test]
    fn empty_input_noop() {
        let s0 = PRNG_STATE.load(Ordering::Relaxed);
        add_entropy(&[]);
        let s1 = PRNG_STATE.load(Ordering::Relaxed);
        assert_eq!(s0, s1, "empty entropy must not change state");
    }
}
