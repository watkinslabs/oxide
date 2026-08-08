// 162 sync / 306 syncfs — whole-filesystem flush family (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sync(2)` — flush every filesystem and every block device to durable
/// storage, in the canonical five-phase order ([`fs::sync::KSYS_SYNC_PHASES`]):
/// data-integrity inode writeback everywhere, `sync_fs(wait=0)` everywhere,
/// `sync_fs(wait=1)` everywhere, then the device-level passes underneath.
///
/// Two properties of that order are the point of it. Each filesystem's commits
/// are KICKED before any of them is WAITED on, so N filesystems cost one commit
/// latency rather than N. And the sweep is over the superblock REGISTRY, not the
/// mount table: an instance whose last mount was lazily detached while file
/// descriptions remain open is still live and still dirty, and a mount-table
/// walk simply never reaches it.
///
/// Always returns 0. A failed pass is not silently lost — the writeback path
/// latches it against the failing inode and its filesystem, so the next
/// `fsync`/`syncfs` reports it exactly once.
/// # C: O(N_sb x dirty + N_disks)
pub fn sys_sync(_args: &SyscallArgs) -> i64 {
    let now = vfs::inode_times::realtime_now_ns();
    fs::sync::ksys_sync(|phase| match phase {
        // `sync_inodes_sb`: the data-integrity metadata pass, which is what
        // forces out every deferred lazy timestamp regardless of age.
        fs::sync::SyncPhase::Inodes => vfs::superblock::iterate_supers(|sb| {
            if !sb.sb_rdonly() { let _ = sb.wb_writeback_pass(true, now); }
        }),
        fs::sync::SyncPhase::FsNoWait => vfs::superblock::iterate_supers(|sb| {
            if !sb.sb_rdonly() { let _ = sb.sync_fs(false); }
        }),
        fs::sync::SyncPhase::FsWait => vfs::superblock::iterate_supers(|sb| {
            if !sb.sb_rdonly() { let _ = sb.sync_fs(true); }
        }),
        fs::sync::SyncPhase::BdevNoWait => sync_bdevs(false),
        fs::sync::SyncPhase::BdevWait   => sync_bdevs(true),
    });
    // Commit the ext4 root running journal transaction (cross-op batching): the
    // per-sb sync flushed dirty pages into the running txn; sync(2) must make it
    // durable. No-op when batching is off / empty / non-ext4 root.
    let _ = ext4::commit_rootfs_journal();
    0
}

/// `sync_bdevs`: the device-level half of `sync(2)`, run after every filesystem
/// above the devices has committed.
///
/// The pass is split into submit and wait because a block device normally holds
/// its own cache of dirty buffers written back asynchronously: submit starts
/// that writeback everywhere, wait collects it. Here a write to a raw block
/// device goes straight to the driver, so there is no deferred device-level
/// cache to submit and the submit half has nothing to start.
///
/// DELIBERATE DEVIATION, stated because it costs something: the wait half takes
/// a durability BARRIER per device rather than waiting on device writeback,
/// since a barrier is the only device-level durability action available with no
/// such writeback to wait for. That is what makes `sync(2)` durable for a device
/// written raw, with no filesystem above it to flush on its behalf — but it also
/// means a device that a filesystem already barriered in the `sync_fs(wait=1)`
/// phase is barriered a second time. Removing the second one requires the
/// device-level writeback this layer does not yet have; until then `sync(2)`
/// pays it, while `syncfs(2)`, freeze and unmount — which do not run this pass —
/// take one barrier per filesystem instead of two.
///
/// Errors are dropped deliberately: `sync(2)` reports 0 regardless, and a device
/// with no filesystem above it has no per-inode latch to record into.
/// # C: O(N_disks)
fn sync_bdevs(wait: bool) {
    if !wait { return; }
    for disk in block::registry::snapshot() { let _ = disk.dev.flush(); }
}

/// `syncfs(fd)` — flush the filesystem CONTAINING `fd` (Linux `sys_syncfs`:
/// resolve `f_path.mnt` → superblock → `sync_filesystem`). Not the fd's inode
/// alone — the whole fs (all its dirty inodes + pending tx + device buffer).
/// Returns 0, -EBADF for a bad fd, or -EIO on flush failure.
/// # C: O(dirty in fs)
pub fn sys_syncfs(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Linux takes the superblock from `fd_file(f)->f_path.dentry->d_sb` — the
    // fd's OWN filesystem — so resolve it from the inode rather than the mount:
    // an fd whose mount lookup fails (anon inode, mnt_id 0) still belongs to a
    // superblock, and `sync_filesystem` on a pseudo-fs is a no-op returning 0.
    let sb = match file.f_inode().i_sb() { Some(s) => s, None => return 0 };
    let ret = sb.sync_filesystem();
    // NOTE: no `ext4::commit_rootfs_journal()` here. ext4's own
    // `SuperOps::sync_fs` already calls `commit_batch()` for EVERY ext4 mount
    // (`rootfs/ops/mountfs.rs`), so the `sync_filesystem` above is the whole
    // job. Calling the root helper as well made syncfs(2) on a tmpfs or procfs
    // fd commit — and, on failure, report EIO for — an unrelated filesystem the
    // caller never named. Linux syncs the one filesystem containing the fd.
    //
    // `ret2 = errseq_check_and_advance(&sb->s_wb_err, &file->f_sb_err);
    // return ret ? ret: ret2;` — a writeback error that
    // happened at ANY point since this fd was opened is reported here exactly
    // once, even though the pass just now succeeded and even if the inode that
    // failed has since been evicted (which is why `mapping_set_error` records
    // into the superblock as well as the inode). Without this, a background
    // writeback failure was simply invisible to `syncfs`.
    let deferred = file.check_and_advance_sb_err();
    match (ret, deferred) {
        // The backend's own errno, not a blanket EIO: an ENOSPC from the
        // journal commit is not an I/O error and `syncfs(2)` propagates
        // whatever `sync_filesystem` returned.
        (Err(e), _) => -(e as i64),
        (Ok(()), Err(e)) => -(e as i64),
        (Ok(()), Ok(())) => 0,
    }
}
