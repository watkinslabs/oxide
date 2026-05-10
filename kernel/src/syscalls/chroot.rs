// `sys_chroot(path)` — slot 161 (F95). Per-task root prefix that
// devfs::lookup applies to absolute paths. Inherited by fork; cleared
// only via explicit chroot. Requires CAP_SYS_CHROOT.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_chroot(path)` — slot 161.
/// # C: O(len)
pub fn sys_chroot(args: &SyscallArgs) -> i64 {
    let p = args.a0;
    if p == 0 || p >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_CHROOT) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    // SAFETY: p validated < USER_VA_END; bounded read via existing helper.
    let bytes = unsafe { crate::devfs::read_user_cstr(p, 256) };
    let s = match bytes.and_then(|b| if b.is_empty() { None } else { core::str::from_utf8(b).ok() }) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    if !s.starts_with('/') { return -(Errno::Einval.as_i32() as i64); }
    // SAFETY: task.root single-mutator per `13§5`; running task on this CPU is the sole writer (chroot only mutates the calling task's root).
    let new_root = unsafe {
        let cur_root = (*cur.root.get()).clone();
        if cur_root == "/" {
            alloc::string::String::from(s)
        } else {
            let mut out = cur_root;
            if out.ends_with('/') { out.pop(); }
            out.push_str(s);
            out
        }
    };
    // SAFETY: same single-mutator invariant.
    unsafe { *cur.root.get() = new_root; }
    0
}
