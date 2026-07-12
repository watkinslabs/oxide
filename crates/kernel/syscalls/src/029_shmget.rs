// 029 shmget — SysV shm creation shim (docs/53 §0). The ipc crate can't reach
// tmpfs, so this ABI-layer shim builds the segment's shared shmem backing (one
// anon tmpfs inode) and hands it to the ipc registry, which holds + maps it.
// Every shmat maps THIS one object MAP_SHARED, so all attaches (and their
// forked children) share the same physical frames — real Linux SysV shm.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_shmget(key, size, shmflg)` — slot 29.
/// # C: O(N_segments) on lookup
pub fn sys_shmget(args: &SyscallArgs) -> i64 {
    let key  = args.a0 as i32;
    let size = args.a1 as usize;
    let flg  = args.a2;
    let cpid = sched::live::current()
        .map(|c| c.vtgid.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(0);
    ipc::sysv_shm::shmget_with_backing(key, size, flg, cpid, || {
        crate::mmap_file::InodeFileBacking::new(::fs::tmpfs::tmpfs_anon_file())
    })
}
