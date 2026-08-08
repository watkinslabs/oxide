// Shared helpers + O_* flag constants for the open(2)/openat(2) family.
// Split out so each syscall lives in its own file (docs/53 §0); the handlers
// are 002_open.rs / 257_openat.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

// The `O_*` bit names and the flag/mode normalisation ladder live in the
// UNGATED `open_flags` module so the hosted suite can exercise them; this file
// is kernel-gated and only wires them to the resolved inode + mount.
pub(crate) use crate::open_flags::{normalize_open_flags, O_ACCMODE, O_CREAT, O_EMPTYPATH,
    O_EXCL, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_RDWR, O_TMPFILE, O_TRUNC, O_WRONLY,
    OPENAT2_REGULAR};

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

/// Open access enforcement, run after path resolution.
///
/// Order is the contract, not an implementation detail:
///
/// 1. `O_TRUNC` on a REGULAR file takes mount write admission FIRST, so a
///    truncating open of a read-only mount is `EROFS` whatever the caller's
///    permissions are — the truncate is part of the open, and the mount cannot
///    host it.
/// 2. The device-node mount policy (`may_open_dev`) stands ahead of the
///    `O_CREAT` permission bypass, so bind mounts of one superblock keep
///    distinct `MNT_NODEV` policy.
/// 3. The full permission ladder (`may_open`): file type, access-mode DAC,
///    append-only inode, `O_NOATIME` ownership.
///
/// The write admission for a PLAIN write-open is deliberately NOT here: it runs
/// after this ladder, in the VFS open path, together with the inode writer
/// reference. That is why `open(path, O_WRONLY)` of a file the caller may not
/// write, on a read-only mount, reports `EACCES` and not `EROFS` — the caller is
/// told the reason that would still stand if the mount were writable.
///
/// The access-mode part is skipped for a freshly `O_CREAT`'d file (its creation
/// already carried the permission decision) and for anonymous inodes
/// (`mnt_id == 0`: ptmx/tty/pipe — governed by their own open hooks); the
/// FLAG-decided rungs still run, because they are decided by the flags rather
/// than by the requested access. An `O_PATH` descriptor takes no access at all.
///
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
    // Truncating a regular file needs the mount to admit a write before the
    // permission ladder runs. Special files (char/block device, FIFO, socket)
    // ignore `O_TRUNC` outright — an open of a device or FIFO addresses the
    // driver, not filesystem data, so a read-only mount must not block it.
    // Without that exemption a service's sandbox (a read-only bind mount of
    // /dev) could not open /dev/kmsg for logging, which fails every sandboxed
    // unit and stalls the boot before the graphical target.
    if mnt_id != 0
        && crate::open_flags::trunc_needs_mount_write(flags, inode.file_type(), created)
    {
        if let Some(m) = vfs::mount::mount_by_id(mnt_id) {
            let mnt_flags = m.flags.load(Ordering::Acquire);
            if (mnt_flags & vfs::mount::MNT_RDONLY) != 0 {
                #[cfg(feature = "debug-mount")]
                trace_open_erofs(inode, mnt_id, flags, mnt_flags, &m.mount_point_str());
                return Some(-(Errno::Erofs.as_i32() as i64));
            }
        }
    }
    // The device-node mount policy consumes the resolved mount identity, so
    // bind mounts of one superblock retain distinct `MNT_NODEV` policy. Ahead
    // of the `O_CREAT` bypass below.
    if mnt_id != 0
        && matches!(inode.file_type(), vfs::types::FileType::CharDev | vfs::types::FileType::BlockDev)
        && !vfs::may_open_dev(mnt_id)
    {
        return Some(-(Errno::Eacces.as_i32() as i64));
    }
    if mnt_id == 0 { return None; }
    let intent = crate::open_flags::open_intent(flags, created);
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = vfs::namei::may_open_at(
        inode, want_read && !created, want_write && !created, intent, &cred)
    {
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
