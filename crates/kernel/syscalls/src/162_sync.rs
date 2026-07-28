// 162 sync / 306 syncfs — whole-filesystem flush family (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sync(2)` — flush ALL mounted filesystems to disk. Linux `ksys_sync`
/// iterates the super_blocks list calling `sync_filesystem` on each. Bind
/// mounts share one superblock, so dedup by `Arc` identity. Always returns 0.
/// # C: O(N_mounts x dirty)
pub fn sys_sync(_args: &SyscallArgs) -> i64 {
    let mounts = vfs::mount::all_mounts();
    let mut synced: alloc::vec::Vec<*const ()> = alloc::vec::Vec::new();
    for m in mounts.iter() {
        let sb = m.sb();
        let key = alloc::sync::Arc::as_ptr(sb) as *const ();
        if synced.contains(&key) { continue; }
        synced.push(key);
        let _ = sb.sync_filesystem();
    }
    // Commit the ext4 root running journal transaction (cross-op batching): the
    // per-sb sync flushed dirty pages into the running txn; sync(2) must make it
    // durable. No-op when batching is off / empty / non-ext4 root.
    let _ = ext4::commit_rootfs_journal();
    0
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
    //  return ret ? ret : ret2;` (`fs/sync.c:162-164`) — a writeback error that
    // happened at ANY point since this fd was opened is reported here exactly
    // once, even though the pass just now succeeded and even if the inode that
    // failed has since been evicted (which is why `mapping_set_error` records
    // into the superblock as well as the inode). Without this, a background
    // writeback failure was simply invisible to `syncfs`.
    let deferred = file.check_and_advance_sb_err();
    match (ret, deferred) {
        (Err(_), _) => -(Errno::Eio.as_i32() as i64),
        (Ok(()), Err(e)) => -(e as i64),
        (Ok(()), Ok(())) => 0,
    }
}
