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
    // Anon-inode / mnt_id==0 fds have no backing filesystem: nothing to sync.
    if let Some(mnt) = file.vfsmount() {
        if mnt.sb().sync_filesystem().is_err() {
            return -(Errno::Eio.as_i32() as i64);
        }
    }
    0
}
