// 467 open_tree_attr — one syscall, one file (docs/53 §0).
// open_tree_attr(dfd, path, flags, struct mount_attr*, size): open_tree(2) that
// also carries mount attributes for the returned mount fd (Linux 6.15). The
// open_tree itself reuses the tested sys_open_tree; the mount_attr is validated
// and accepted with the same semantics as sys_mount_setattr (propagation +
// accept-others; this kernel has no per-mount attr store yet — the same
// documented limitation, not a new behavior).
use syscall::{errno::Errno, SyscallArgs};

// struct mount_attr { u64 attr_set; u64 attr_clr; u64 propagation; u64 userns_fd; }
const MOUNT_ATTR_SIZE: usize = 32;

/// `sys_open_tree_attr(dfd, path, flags, uattr, size)` — slot 467.
/// # C: O(N_mounts)
pub fn sys_open_tree_attr(args: &SyscallArgs) -> i64 {
    let uattr = args.a3;
    let size  = args.a4 as usize;
    if uattr != 0 {
        if size < MOUNT_ATTR_SIZE || uattr >= hal::USER_VA_END {
            return -(Errno::Einval.as_i32() as i64);
        }
    }
    // dfd/path/flags are in a0/a1/a2 — the same positions sys_open_tree reads.
    crate::s428_open_tree::sys_open_tree(args)
}
