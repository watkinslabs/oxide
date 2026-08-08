// Shared helpers + O_* flag constants for the open(2)/openat(2) family.
// Split out so each syscall lives in its own file (docs/53 §0); the handlers
// are 002_open.rs / 257_openat.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

pub(crate) const O_CREAT:     u32 = 0o100;
/// `O_EXCL` (asm-generic, both arches): with `O_CREAT`, an existing final
/// component → `EEXIST` (Linux `do_last`/`lookup_open`).
pub(crate) const O_EXCL:      u32 = 0o200;
pub(crate) const O_TRUNC:     u32 = 0o1000;
pub(crate) const O_APPEND:    u32 = 0o2000;
pub(crate) const O_DIRECTORY: u32 = 0o200000;
// O_* flag VALUES are arch-specific (Linux fcntl UAPI per-arch overrides):
// x86_64 = asm-generic (O_NOFOLLOW=0o400000); aarch64 uses the arm override
// (O_NOFOLLOW=0o100000, while 0x20000 is O_LARGEFILE which musl-aarch64 sets).
#[cfg(target_arch = "x86_64")]
pub(crate) const O_NOFOLLOW:  u32 = 0o400000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_NOFOLLOW:  u32 = 0o100000;
/// `__O_TMPFILE` per the Linux fcntl UAPI (full O_TMPFILE = this | O_DIRECTORY).
pub(crate) const O_TMPFILE:   u32 = 0o20000000;
/// `O_PATH` (asm-generic, both arches): an fd-reference open with no read/write
/// access — bypasses `may_open`'s access-mode permission check.
pub(crate) const O_PATH:      u32 = 0o10000000;
pub(crate) const O_CLOEXEC:   u32 = 0o2000000;
/// `O_ACCMODE` mask + the writable access modes.
pub(crate) const O_ACCMODE:   u32 = 0o3;
pub(crate) const O_WRONLY:    u32 = 0o1;
pub(crate) const O_RDWR:      u32 = 0o2;
/// `O_NONBLOCK` (asm-generic, both arches): a non-blocking conflicting open
/// fails the lease-break with `EWOULDBLOCK` instead of waiting.
pub(crate) const O_NONBLOCK:  u32 = 0o4000;
const O_NOCTTY:    u64 = 0o400;
const O_DSYNC:     u64 = 0o10000;
const O_ASYNC:     u64 = 0o20000;
const O_DIRECT:    u64 = 0o40000;
const O_LARGEFILE: u64 = 0o100000;
const O_NOATIME:   u64 = 0o1000000;
const __O_SYNC:    u64 = 0o4000000;
const O_SYNC:      u64 = 0o4010000;
pub(crate) const O_EMPTYPATH: u64 = 0o400000000;
pub(crate) const OPENAT2_REGULAR: u64 = 0o40000000000;
const VALID_OPEN_FLAGS: u64 = O_CREAT as u64 | O_EXCL as u64 | O_TRUNC as u64
    | O_APPEND as u64
    | O_DIRECTORY as u64 | O_NOFOLLOW as u64 | O_TMPFILE as u64 | O_PATH as u64
    | O_CLOEXEC as u64 | O_ACCMODE as u64 | O_NONBLOCK as u64 | O_NOCTTY
    | O_DSYNC | O_ASYNC | O_DIRECT | O_LARGEFILE | O_NOATIME | O_SYNC | O_EMPTYPATH;
const VALID_OPENAT2_FLAGS: u64 = VALID_OPEN_FLAGS | OPENAT2_REGULAR;
const O_PATH_FLAGS: u64 = O_DIRECTORY as u64 | O_NOFOLLOW as u64 | O_PATH as u64
    | O_CLOEXEC as u64 | O_EMPTYPATH;

#[cfg(feature = "debug-mount")]
fn trace_open_erofs(inode: &vfs::InodeRef, mnt_id: u64, flags: u32, mnt_flags: u64, mp: &str) {
    use core::sync::atomic::Ordering;
    klog::write_raw(b"[OPEN-EROFS] tid=");
    if let Some(c) = sched::live::current() {
        klog::write_dec_u64(c.tid as u64);
        klog::write_raw(b" tgid="); klog::write_dec_u64(c.tgid.load(Ordering::Acquire) as u64);
        klog::write_raw(b" ns="); klog::write_dec_u64(c.mount_namespace_id().unwrap_or(0));
        klog::write_raw(b" name="); { let comm = c.comm_bytes(); klog::write_raw(sched::Task::comm_trim(&comm).as_bytes()); }
    } else {
        klog::write_raw(b"0 tgid=0 ns=0 name=<none>");
    }
    klog::write_raw(b" mnt_id="); klog::write_dec_u64(mnt_id);
    klog::write_raw(b" mnt_flags=0x"); klog::write_hex_u64(mnt_flags);
    klog::write_raw(b" open_flags=0x"); klog::write_hex_u64(flags as u64);
    klog::write_raw(b" mp="); klog::write_raw(mp.as_bytes());
    klog::write_raw(b" ftype=");
    match inode.file_type() {
        vfs::types::FileType::Regular => klog::write_raw(b"regular"),
        vfs::types::FileType::Directory => klog::write_raw(b"dir"),
        vfs::types::FileType::Symlink => klog::write_raw(b"symlink"),
        vfs::types::FileType::CharDev => klog::write_raw(b"char"),
        vfs::types::FileType::BlockDev => klog::write_raw(b"block"),
        vfs::types::FileType::Fifo => klog::write_raw(b"fifo"),
        vfs::types::FileType::Socket => klog::write_raw(b"socket"),
    }
    klog::write_raw(b"\n");
}

/// Linux `build_open_how` / `build_open_flags` validation needed before path
/// mutation. Legacy open/openat mask unsupported bits and let `O_PATH` strip
/// every non-path flag; openat2 keeps the full 64-bit flags word for unknown-bit
/// rejection. # C: O(1)
pub(crate) fn normalize_open_flags(flags: u64, mode: u64, openat2: bool) -> Result<(u32, u32), i64> {
    let mut f = flags;
    let mut m = mode;
    if !openat2 {
        f &= VALID_OPEN_FLAGS;
        m &= 0o7777;
        if (f & O_PATH as u64) != 0 { f &= O_PATH_FLAGS; }
        if (f & (O_CREAT as u64 | O_TMPFILE as u64)) == 0 { m = 0; }
    } else {
        if (f & !VALID_OPENAT2_FLAGS) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
        if (f & (O_CREAT as u64 | O_TMPFILE as u64)) != 0 {
            if (m & !0o7777) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
        } else if m != 0 {
            return Err(-(Errno::Einval.as_i32() as i64));
        }
        if (f & O_PATH as u64) != 0 && (f & !O_PATH_FLAGS) != 0 {
            return Err(-(Errno::Einval.as_i32() as i64));
        }
    }
    if (f & (O_DIRECTORY as u64 | O_CREAT as u64)) == (O_DIRECTORY as u64 | O_CREAT as u64) {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    if (f & O_TMPFILE as u64) != 0 {
        if (f & O_DIRECTORY as u64) == 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
        let acc = (f as u32) & O_ACCMODE;
        if acc != O_WRONLY && acc != O_RDWR { return Err(-(Errno::Einval.as_i32() as i64)); }
    }
    if (f & (O_DIRECTORY as u64 | OPENAT2_REGULAR)) == (O_DIRECTORY as u64 | OPENAT2_REGULAR) {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    if (f & __O_SYNC) != 0 { f |= O_DSYNC; }
    Ok((f as u32, m as u32))
}

/// Linux `do_open` access enforcement, run after path resolution: `EROFS` for a
/// write through a read-only mount (`mnt_want_write`), then the `may_open` DAC
/// check (EACCES / EISDIR). The DAC check is skipped for a freshly `O_CREAT`'d
/// file (Linux passes acc_mode=0), for `O_PATH` descriptors, and for anonymous
/// inodes (`mnt_id == 0`: ptmx/tty/pipe — governed by their own open hooks).
/// Returns `Some(neg_errno)` to fail the open, `None` to allow it.
/// # C: O(ngroups)
pub(crate) fn enforce_open_perm(
    inode: &vfs::InodeRef,
    mnt_id: u64,
    flags: u32,
    created: bool,
) -> Option<i64> {
    use core::sync::atomic::Ordering;
    if (flags & O_PATH) != 0 { return None; }
    let accmode    = flags & O_ACCMODE;
    let want_write = accmode == O_WRONLY || accmode == O_RDWR || (flags & O_TRUNC) != 0;
    let want_read  = accmode != O_WRONLY;
    // EROFS: writing through a read-only mount (Linux `mnt_want_write`) — BUT
    // Linux EXEMPTS special files. `do_dentry_open` skips the write-access
    // check when `special_file(inode->i_mode)` (char/block device, FIFO,
    // socket): writing to a device or FIFO doesn't modify the filesystem, so a
    // read-only mount must not block it. Without this exemption a service's
    // sandbox (systemd bind-mounts /dev read-only) could not open /dev/kmsg
    // O_WRONLY for logging → the child aborts with EXIT_NAMESPACE(226), which
    // fails EVERY sandboxed unit (dbus-broker, systemd-udevd, logind, gdm, …)
    // and stalls the whole boot before the graphical target.
    let special = matches!(
        inode.file_type(),
        vfs::types::FileType::CharDev | vfs::types::FileType::BlockDev
            | vfs::types::FileType::Fifo | vfs::types::FileType::Socket
    );
    if want_write && mnt_id != 0 && !special {
        if let Some(m) = vfs::mount::mount_by_id(mnt_id) {
            let mnt_flags = m.flags.load(Ordering::Acquire);
            if (mnt_flags & vfs::mount::MNT_RDONLY) != 0 {
                #[cfg(feature = "debug-mount")]
                trace_open_erofs(inode, mnt_id, flags, mnt_flags, &m.mount_point_str());
                return Some(-(Errno::Erofs.as_i32() as i64));
            }
        }
    }
    // Linux `may_open` applies `may_open_dev(path)` BEFORE the `O_CREAT`
    // permission bypass. The VFS helper consumes the resolved mount identity,
    // so bind mounts of one superblock retain distinct MNT_NODEV policy.
    if mnt_id != 0
        && matches!(inode.file_type(), vfs::types::FileType::CharDev | vfs::types::FileType::BlockDev)
        && !vfs::may_open_dev(mnt_id)
    {
        return Some(-(Errno::Eacces.as_i32() as i64));
    }
    if created || mnt_id == 0 { return None; }
    if let Err(e) = vfs::may_open(inode, want_read, want_write, &crate::pathresolve::current_cred()) {
        return Some(-(e as i64));
    }
    None
}

/// Lease-break on a conflicting open (Linux `do_open` → `break_lease`). When
/// another open description holds a lease on `inode` that conflicts with this
/// open (a read lease vs a write/truncate open, OR a write lease vs ANY open),
/// signal the lease holder (its `F_SETSIG` signal or default `SIGIO`) and BLOCK
/// this opener until the holder downgrades/releases the lease or `lease_break_time`
/// (45 s) elapses, at which point the lease is force-broken and the open proceeds.
/// `O_NONBLOCK` returns `EWOULDBLOCK` instead of waiting; a pending signal aborts
/// the wait with `EINTR` (Linux `-ERESTARTSYS`).
///
/// Zero-cost on the common path: `lease_conflict` reads a single relaxed counter
/// and returns `false` immediately when no lease exists anywhere — the boot/
/// no-lease open never takes a lock or scans. `Some(neg_errno)` fails the open;
/// `None` lets it proceed. # C: O(1) common; O(N_leases) + wait when a lease conflicts
pub(crate) fn break_lease_for_open(inode: &vfs::InodeRef, flags: u32) -> Option<i64> {
    let accmode = flags & O_ACCMODE;
    let writes = accmode == O_WRONLY || accmode == O_RDWR || (flags & O_TRUNC) != 0;
    // Fast path: no conflicting lease (almost always). One atomic load at zero.
    if !vfs::file::lease_conflict(inode, writes) { return None; }
    // A conflict exists — signal the holder(s) once (Linux `__break_lease`).
    vfs::file::lease_break_signal(inode, writes);
    if (flags & O_NONBLOCK) != 0 { return Some(-(Errno::Eagain.as_i32() as i64)); }
    let cur = match sched::live::current() { Some(c) => c, None => return None };
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")] let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let deadline = now().saturating_add(vfs::file::LEASE_BREAK_NS);
    // Wait for the holder to downgrade/release; force-break on timeout. Yields
    // the CPU like F_SETLKW; interruptible by a deliverable signal.
    while vfs::file::lease_conflict(inode, writes) {
        if sched::live::sigpend::deliverable_signals(cur) != 0 {
            return Some(-(Errno::Eintr.as_i32() as i64));
        }
        if now() >= deadline { vfs::file::lease_force_break(inode, writes); break; }
        // SAFETY: process ctx; preempt-off; runqueue installed; voluntary schedule() yields the CPU; we stay Runnable so the scheduler reselects us.
        unsafe { sched::live::schedule::schedule(); }
    }
    None
}
