// 095 umask — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_umask(mask)` — slot 95. Installs `mask & S_IRWXUGO` on the caller's
/// SHARED filesystem owner (Linux `current->fs->umask`, so every CLONE_FS
/// sibling sees it) and returns the previous mask. Cannot fail.
/// # C: O(1)
pub fn sys_umask(args: &SyscallArgs) -> i64 {
    let new_mask = args.a0 as u32;
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return (new_mask & sched::task::UMASK_MASK) as i64,
    };
    cur.swap_umask(new_mask) as i64
}
