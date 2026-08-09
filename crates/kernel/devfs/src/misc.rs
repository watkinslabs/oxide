// Misc char devices per docs/16 + docs/19: /dev/null, /dev/zero,
// /dev/full, /dev/random, /dev/urandom. v1 minimal Inode impls;
// register at boot via `crate::register`.


use core::sync::atomic::{AtomicU64, Ordering};

use alloc::sync::Arc;
use vfs::{FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError};
use vfs::{FileOps, default_file_ops, default_inode_ops, mk_mode};

/// Build a `CharDev` inode with the misc-device perm/rdev shape: `i_private`
/// is unused (the data path is a stateless `i_fop`), `fsid` is `DEVFS_FSID`.
/// # C: O(1)
fn char_inode(ino: vfs::Ino, perm: u16, rdev: u32, fop: Arc<dyn FileOps>) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, perm), default_inode_ops(), fop)
        .fsid(crate::DEVFS_FSID).rdev(rdev).build()
}

/// `char_inode` for a kernel-provided PUBLIC device (`/dev/null`, `/dev/zero`,
/// `/dev/full`, `/dev/random`, `/dev/urandom`) — a single shared inode across
/// all mount namespaces whose world-rw perms must survive systemd's per-service
/// device-node chowns (see [`vfs::Inode::mark_public_device`]). # C: O(1)
fn public_char_inode(ino: vfs::Ino, rdev: u32, fop: Arc<dyn FileOps>) -> InodeRef {
    let i = char_inode(ino, 0o666, rdev, fop);
    i.mark_public_device();
    i
}

/// Boot-time smoke test: each device's `f_op` read fills the right bytes.
/// `/dev/zero` returns NUL, `/dev/null` returns 0 (EOF), `/dev/random`
/// fills with non-deterministic bytes (we just check len). Run from
/// `kernel_main` after `crate::init()`.
/// # SAFETY: caller is the boot path; PMM up; single-CPU pre-init.
/// # C: O(1) per inode
pub fn smoke_test() {
    let zero = make_zero_inode();
    let null = make_null_inode();
    let random = make_random_inode();
    let full = make_full_inode();

    let mut buf = [0xAAu8; 16];
    let n = zero.read(0, &mut buf).expect("zero.read");
    kassert!(n == 16, "zero read len");
    for b in buf.iter() { kassert!(*b == 0, "zero read fills NUL"); }

    let mut buf2 = [0xBBu8; 16];
    let n = null.read(0, &mut buf2).expect("null.read");
    kassert!(n == 0, "null read EOF");
    for b in buf2.iter() { kassert!(*b == 0xBB, "null read leaves buf"); }

    let mut buf3 = [0u8; 32];
    let n = random.read(0, &mut buf3).expect("random.read");
    kassert!(n == 32, "random read len");
    let nz = buf3.iter().filter(|b| **b != 0).count();
    kassert!(nz > 0, "random read produces non-zero bytes");

    let n = null.write(0, b"hello").expect("null.write");
    kassert!(n == 5, "null write accepts all");
    let n = zero.write(0, b"hello").expect("zero.write");
    kassert!(n == 5, "zero write accepts all");
    let r = full.write(0, b"hello");
    kassert!(r.is_err(), "full write returns Eio");

    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  dev-misc-smoke: ok\n");
    }
}

use hal::kassert;

/// `/dev/null` — read returns 0 (EOF), write discards.
struct NullFileOps;
impl FileOps for NullFileOps {
    fn read(&self, _i: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}
/// `/dev/null` inode (1:3 mem/null, `0o666`). # C: O(1)
pub fn make_null_inode() -> InodeRef { public_char_inode(crate::uapi::INO_NULL, crate::uapi::DEV_MEM_NULL, Arc::new(NullFileOps)) }

/// Static symlink with a fixed target — backs the standard `/dev`
/// links `stdin`/`stdout`/`stderr`/`fd` that every Linux system
/// carries (→ `/proc/self/fd/*`). Shells (`< /dev/stdin`,
/// `> /dev/stdout`), bash process substitution (`/dev/fd/<n>`), and
/// scripts depend on them. Built with the target as the inline `i_link`
/// body, so `get_link` reads it without a custom `i_op->readlink`.
/// # C: O(target)
pub fn make_symlink_inode(target: &'static [u8], ino: vfs::Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops())
        .fsid(crate::DEVFS_FSID)
        .size(target.len() as u64)
        .link(target.to_vec().into_boxed_slice())
        .build()
}

/// `/dev/kmsg` — Linux kernel ring-buffer file. Reads pull bytes from
/// `klog::ring_read` (the in-memory dmesg log); writes inject a userspace
/// record into the ring + console (early systemd / `logger` / journald).
/// Each open's reader cursor is reset to 0 at open — repeated
/// `cat /dev/kmsg` invocations from userspace each see the
/// available tail of the ring.
struct KmsgFileOps;
impl FileOps for KmsgFileOps {
    fn read(&self, _i: &Inode, off: u64, b: &mut [u8]) -> KResult<usize> {
        let (n, _next) = klog::ring_read(off as usize, b);
        Ok(n)
    }
    /// `/dev/kmsg` is always writable; POLL_IN only when the reader's cursor
    /// (`File::pos`) is behind the ring head (unread messages). Without this,
    /// the default always-`POLL_IN` poll() busy-looped journald's epoll on
    /// /dev/kmsg ("Looping too fast"). # C: O(1)
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll_file(&self, _i: &Inode, pos: u64) -> u32 {
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
    fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        kmsg_write_record(b);
        Ok(b.len())
    }
}

/// One vectored `/dev/kmsg` write, joined into a single record before it
/// reaches the log (Linux `devkmsg_write` consumes the whole `iov_iter`).
/// Split out from the device method so the joining is provable without a
/// `File` to hang it off.
/// # C: O(sum lens)
fn kmsg_write_iter(bufs: &[&[u8]]) -> KResult<usize> {
    let total = bufs.iter().try_fold(0usize, |sum, b| sum.checked_add(b.len()))
        .ok_or(VfsError::Einval)?;
    if bufs.len() == 1 { kmsg_write_record(bufs[0]); return Ok(total); }
    let mut record = alloc::vec::Vec::new();
    record.try_reserve_exact(total).map_err(|_| VfsError::Enomem)?;
    for b in bufs { record.extend_from_slice(b); }
    kmsg_write_record(&record);
    Ok(total)
}

/// `/dev/kmsg` write body (Linux `devkmsg_write`): strip an optional leading
/// `<N>` syslog-priority prefix, inject one record into the kernel log ring,
/// ensuring a trailing newline. Shared by `KmsgFileOps` (devfs inode) and
/// `MemCharDevOps` (mknod'd node). # C: O(len)
fn kmsg_write_record(b: &[u8]) {
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
}
/// `/dev/kmsg` inode (1:11 mem/kmsg, `0o644`). # C: O(1)
pub fn make_kmsg_inode() -> InodeRef { char_inode(crate::uapi::INO_KMSG, 0o644, crate::uapi::DEV_MEM_KMSG, Arc::new(KmsgFileOps)) }

/// `/dev/zero` — read fills with NUL, write discards.
struct ZeroFileOps;
impl FileOps for ZeroFileOps {
    fn read(&self, _i: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> {
        for x in b.iter_mut() { *x = 0; }
        Ok(b.len())
    }
    fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}
/// `/dev/zero` inode (1:5 mem/zero, `0o666`). # C: O(1)
pub fn make_zero_inode() -> InodeRef { public_char_inode(crate::uapi::INO_ZERO, crate::uapi::DEV_MEM_ZERO, Arc::new(ZeroFileOps)) }

/// `/dev/full` — read fills with NUL like /dev/zero; write
/// returns -ENOSPC. POSIX-shaped so libc `posix_fallocate`-on-
/// /dev/full tests work.
struct FullFileOps;
impl FileOps for FullFileOps {
    fn read(&self, _i: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> {
        for x in b.iter_mut() { *x = 0; }
        Ok(b.len())
    }
    fn write(&self, _i: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}
/// `/dev/full` inode (1:7 mem/full, `0o666`). # C: O(1)
pub fn make_full_inode() -> InodeRef { public_char_inode(crate::uapi::INO_FULL, crate::uapi::DEV_MEM_FULL, Arc::new(FullFileOps)) }

/// Mix externally-sourced entropy bytes into the kernel CSPRNG (Linux
/// `add_device_randomness`). Empty input is a no-op.
/// # C: O(bytes.len())
pub fn add_entropy(bytes: &[u8]) {
    if bytes.is_empty() { return; }
    crng::add_entropy(bytes);
}

/// Mix entropy from a hardware generator and credit it (Linux
/// `add_hwgenerator_randomness`) — unlike `add_entropy`, this is what marks
/// the pool ready. Only a real hardware source may call it.
/// # C: O(bytes.len())
pub fn add_hw_entropy(bytes: &[u8]) {
    if bytes.is_empty() { return; }
    crng::add_hw_entropy(bytes);
}

/// One CSPRNG word. Callers wanting a buffer use `random_fill`.
/// # C: O(1)
pub fn random_u64() -> u64 { crng::next_u64() }

/// Hardware-entropy source hook. `/dev/hwrng` reads route here; the hwrng
/// driver installs its `fill` function from probe and clears it from remove.
/// Stored as a raw fn pointer so devfs needn't depend on the driver crate
/// (same pattern as the dir-overlay hook). 0 = absent.
static HWRNG_SOURCE: AtomicU64 = AtomicU64::new(0);
type HwRngFn = fn(&mut [u8]) -> usize;

/// Install the hardware-entropy source. Until installed, `/dev/hwrng` reads
/// return 0 (EOF) rather than fabricating bytes.
/// # C: O(1)
pub fn set_hwrng_source(f: HwRngFn) {
    HWRNG_SOURCE.store(f as usize as u64, Ordering::Release);
    // Same source feeds the kernel CSPRNG's reseed (Linux registers a hwrng
    // as an entropy source, not merely as a `/dev/hwrng` read path).
    crng::set_bulk_source(f);
}

/// Clear the hardware-entropy source during driver remove. # C: O(1)
pub fn clear_hwrng_source() {
    HWRNG_SOURCE.store(0, Ordering::Release);
    crng::clear_bulk_source();
}

/// `/dev/hwrng` — Linux hardware-RNG char device. Each read pulls fresh
/// bytes from the installed virtio-rng source; with no source installed
/// (no device) reads return 0 (EOF), matching a `/dev/hwrng` whose backing
/// hwrng has no current_rng. Real hardware entropy, NOT the LCG.
struct HwRngFileOps;
impl FileOps for HwRngFileOps {
    fn read(&self, _i: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> {
        let p = HWRNG_SOURCE.load(Ordering::Acquire);
        if p == 0 { return Ok(0); }
        // SAFETY: p was stored from a `HwRngFn` via set_hwrng_source; the
        // function pointer ABI matches and it is only ever set to the
        // virtio-rng `fill` entry, which reads device entropy into `b`.
        let f: HwRngFn = unsafe { core::mem::transmute(p as usize) };
        Ok(f(b))
    }
    fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}
/// `/dev/hwrng` inode (10:183 misc/hw_random, `0o644`). # C: O(1)
pub fn make_hwrng_inode() -> InodeRef { char_inode(crate::uapi::INO_HWRNG, 0o644, crate::uapi::DEV_MISC_HWRNG, Arc::new(HwRngFileOps)) }

/// `/dev/autofs` — misc char device for the built-in autofs control ABI.
/// No data path (default `f_op` → `EINVAL` on a CharDev read/write).
/// # C: O(1)
pub fn make_autofs_inode() -> InodeRef { char_inode(crate::uapi::INO_AUTOFS, 0o600, crate::uapi::DEV_MISC_AUTOFS, default_file_ops()) }

/// Fill `b` from the kernel CSPRNG — the shared `/dev/random`,
/// `/dev/urandom` and `sys_getrandom` body (`crng`). # C: O(b.len())
pub fn random_fill(b: &mut [u8]) { crng::fill(b); }

/// `/dev/random` and `/dev/urandom` — ChaCha20 CSPRNG output (`crng`).
/// Linux hands both minors the same generator; neither blocks once the pool
/// is up.
struct RandomFileOps;
impl FileOps for RandomFileOps {
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, _i: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> {
        random_fill(b);
        Ok(b.len())
    }
    fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}
/// `/dev/random` inode (1:8 mem/random, `0o666`). # C: O(1)
pub fn make_random_inode() -> InodeRef { public_char_inode(crate::uapi::INO_RANDOM, crate::uapi::DEV_MEM_RANDOM, Arc::new(RandomFileOps)) }

/// `/dev/urandom` inode (1:9 mem/urandom, `0o666`). # C: O(1)
pub fn make_urandom_inode() -> InodeRef { public_char_inode(crate::uapi::INO_URANDOM, crate::uapi::DEV_MEM_URANDOM, Arc::new(RandomFileOps)) }

/// The `mem` char driver (Linux major 1) — ONE
/// `CharDevOps` backing every mem minor, dispatching by minor to the SAME
/// behaviour the devfs built-in inodes expose. Registered at boot via
/// `register_chrdev(1, …)`.
///
/// Why this must exist: the built-in `/dev/null`,`/dev/zero`,… inodes bake
/// their `f_op` directly into the devfs node, so they never registered a
/// driver in the `cdev` registry. A userspace `mknod(path, S_IFCHR, MKDEV(1,3))`
/// — which systemd's `PrivateDevices=`/`clone_device_node` performs to clone
/// the standard nodes into a service's private `/dev` tmpfs — builds a
/// `DeviceFileOps` node that dispatches through `lookup_chrdev(1:3)`. With no
/// driver registered that lookup MISSED and `open(2)` returned `ENXIO`
/// ("polkitd: Error opening /dev/null: No such device or address"). Registering
/// the mem major makes the mknod'd node resolve to the real driver, matching
/// Linux where `/dev/null` works via BOTH devtmpfs and a hand-`mknod`ed node.
///
/// Unknown minors return `ENXIO` (Linux mem `memory_open` rejects unregistered
/// minors), so a stray `mknod c 1 42` still errors like Linux.
pub struct MemCharDevOps;
impl vfs::CharDevOps for MemCharDevOps {
    /// # C: O(buf.len())
    fn read(&self, devt: vfs::Devt, off: u64, buf: &mut [u8]) -> KResult<usize> {
        match devt.minor() {
            3 => Ok(0),                                                    // null: EOF
            5 | 7 => { for x in buf.iter_mut() { *x = 0; } Ok(buf.len()) } // zero/full
            8 | 9 => { random_fill(buf); Ok(buf.len()) }                   // random/urandom
            11 => { let (n, _next) = klog::ring_read(off as usize, buf); Ok(n) } // kmsg
            _ => Err(VfsError::Enxio),
        }
    }
    /// # C: O(buf.len())
    fn write(&self, devt: vfs::Devt, _off: u64, buf: &[u8]) -> KResult<usize> {
        match devt.minor() {
            3 | 5 | 8 | 9 => Ok(buf.len()),        // null/zero/random discard
            7 => Err(VfsError::Eio),               // full: mirrors FullFileOps (write fails)
            11 => { kmsg_write_record(buf); Ok(buf.len()) }
            _ => Err(VfsError::Enxio),
        }
    }

    /// `/dev/kmsg` is record-oriented: ONE `writev` is ONE record, however many
    /// iovecs carry it (Linux `devkmsg_write` consumes the whole `iov_iter`).
    ///
    /// The stream default writes each iovec separately, which turns every
    /// vectored log line into that many records. The system log daemon sends a
    /// line as identifier, `[pid]: `, and message in separate iovecs, so a
    /// console showed `systemd`, `[1]: ` and the message as three timestamped
    /// lines instead of one — the boot log became unreadable exactly when it
    /// matters most.
    ///
    /// Every other minor here is a stream (`/dev/null`, `/dev/zero`,
    /// `/dev/random`), so they keep the default.
    /// # C: O(sum lens)
    fn write_iter_file(&self, devt: vfs::Devt, file: &vfs::File, off: u64,
        bufs: &[&[u8]], nonblock: bool) -> KResult<usize>
    {
        if devt.minor() != 11 {
            return vfs::file_ops::stream_write_iter_with(off, bufs, |pos, buf| {
                if nonblock { self.write_nonblock_file(devt, file, pos, buf) }
                else { self.write_file(devt, file, pos, buf) }
            });
        }
        kmsg_write_iter(bufs)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// One `writev` to `/dev/kmsg` is ONE record, however many iovecs carry
    /// it. The system log daemon sends a line as identifier, `[pid]: ` and
    /// message in separate iovecs; splitting them gives every fragment its own
    /// timestamp, which is what made the boot console unreadable.
    #[test]
    fn a_vectored_kmsg_write_is_one_record() {
        let before = klog::ring_total();
        let ops = MemCharDevOps;
        let devt = vfs::Devt::new(1, 11);
        let _ = (&ops, devt);
        let bufs: [&[u8]; 3] = [b"systemd", b"[1]: ", b"Detected virtualization kvm.\n"];
        let n = kmsg_write_iter(&bufs).unwrap();
        assert_eq!(n, bufs.iter().map(|b| b.len()).sum::<usize>(), "reports every byte accepted");

        let mut out = alloc::vec![0u8; klog::ring_total() - before];
        let (got, _) = klog::ring_read(before, &mut out);
        let text = core::str::from_utf8(&out[..got]).unwrap_or("");
        assert!(text.contains("systemd[1]: Detected virtualization kvm."),
            "the three iovecs must reach the log as one line: {text:?}");
        assert_eq!(text.matches('\n').count(), 1, "one record, one newline: {text:?}");
    }

    /// Mixing entropy must perturb the CSPRNG: the stream after a mix
    /// differs from the stream without it.
    #[test]
    fn add_entropy_changes_state() {
        let before = random_u64();
        add_entropy(&[0x42, 0x99, 0x01, 0xFE]);
        let after = random_u64();
        assert_ne!(before, after, "entropy mix must perturb the stream");
    }

    /// Different entropy inputs must drive the state to different places.
    #[test]
    fn distinct_inputs_distinct_state() {
        add_entropy(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let a = random_u64();
        add_entropy(&[8, 7, 6, 5, 4, 3, 2, 1]);
        let b = random_u64();
        assert_ne!(a, b, "distinct entropy inputs must diverge");
    }

    /// `random_fill` must fill the whole buffer, including unaligned tails.
    #[test]
    fn random_fill_covers_unaligned_lengths() {
        for n in [1usize, 7, 8, 63, 65] {
            let mut buf = alloc::vec![0u8; n];
            random_fill(&mut buf);
            assert_eq!(buf.len(), n);
            assert!(buf.iter().any(|&b| b != 0), "random_fill({n}) wrote nothing");
        }
    }

    /// A mknod'd char node on major 1 (systemd `PrivateDevices=` clones the
    /// standard nodes this way) must dispatch through the registered `mem`
    /// driver, not miss the cdev registry and return `ENXIO`. This is the
    /// polkitd "Error opening /dev/null: No such device or address" bug.
    #[test]
    fn mem_driver_dispatches_after_register() {
        use vfs::{Devt, VfsError};
        // Without register_chrdev the cdev registry has no major 1, so a
        // mknod'd node's lookup_chrdev(1:3) MISSES → the polkitd ENXIO.
        // After registering the mem driver the same lookup resolves.
        vfs::register_chrdev(1, alloc::sync::Arc::new(super::MemCharDevOps));
        let ops = vfs::lookup_chrdev(Devt::new(1, 3)).expect("mem driver registered on major 1");

        // /dev/null (1:3): read = EOF, write = swallow all.
        let mut buf = [0xAAu8; 8];
        assert_eq!(ops.read(Devt::new(1, 3), 0, &mut buf), Ok(0), "null read EOF");
        assert_eq!(buf, [0xAAu8; 8], "null read leaves buf untouched");
        assert_eq!(ops.write(Devt::new(1, 3), 0, b"discarded"), Ok(9), "null write swallows");
        assert!(ops.open(Devt::new(1, 3)).is_ok(), "null open ok (not ENXIO)");

        // /dev/zero (1:5): read zero-fills.
        let mut z = [0xAAu8; 4];
        assert_eq!(ops.read(Devt::new(1, 5), 0, &mut z), Ok(4));
        assert_eq!(z, [0u8; 4], "zero read fills NUL");

        // /dev/full (1:7): write fails like FullFileOps.
        assert_eq!(ops.write(Devt::new(1, 7), 0, b"x"), Err(VfsError::Eio), "full write fails");

        // Unknown minor still errors (Linux mem rejects unregistered minors).
        assert_eq!(ops.read(Devt::new(1, 42), 0, &mut buf), Err(VfsError::Enxio));
    }
}
