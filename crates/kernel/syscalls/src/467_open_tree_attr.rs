// 467 open_tree_attr — one syscall, one file (docs/53 §0).
// `open_tree(2)` that also carries mount attributes for the returned mount fd.
//
// Linux composes it out of the two syscalls that already exist: `vfs_open_tree`
// builds the file, then `wants_mount_setattr` + `do_mount_setattr` apply the
// attribute block to the file's own path, and the fd is PUBLISHED only if both
// halves succeeded. This slot does the same by calling `sys_open_tree`'s
// already-tested body and then driving `sys_mount_setattr` against the new fd
// with `AT_EMPTY_PATH` — the path form that reaches the detached mount object.
// A failed attribute application closes the fd instead of returning it, so the
// caller never receives a descriptor whose attributes were silently dropped
// (the previous shim validated the block and then ignored it entirely).
#![cfg(target_os = "oxide-kernel")]

use syscall::{errno::Errno, SyscallArgs};

/// `struct mount_attr` version 0: `{ u64 attr_set, attr_clr, propagation, userns_fd }`.
const MOUNT_ATTR_SIZE: usize = 32;

/// `sys_open_tree_attr(dfd, path, flags, uattr, size)` — slot 467.
/// # C: O(N_mounts)
pub fn sys_open_tree_attr(args: &SyscallArgs) -> i64 {
    let uattr = args.a3;
    let size = args.a4 as usize;
    // Ahead of the open_tree flag word: a NULL block with a nonzero size.
    let want_attr = match crate::open_tree_policy::attr_block_present(uattr, size) {
        Ok(w) => w, Err(rv) => return rv,
    };
    let f = match crate::open_tree_policy::parse(args.a2) { Ok(f) => f, Err(rv) => return rv };
    let fd = crate::s428_open_tree::open_tree_decided(args, f);
    if fd < 0 || !want_attr { return fd; }
    if size < MOUNT_ATTR_SIZE {
        close_fd(fd as i32);
        return -(Errno::Einval.as_i32() as i64);
    }
    // `AT_RECURSIVE` carries through to the attribute application exactly as it
    // carried through to the clone; the other open_tree bits are not
    // mount_setattr bits and must not leak into its `VALID_AT_FLAGS` check.
    let at_flags = syscall::at::AT_EMPTY_PATH as u64
        | if f.recursive { syscall::at::AT_RECURSIVE as u64 } else { 0 };
    let rv = crate::s442_mount_setattr::mount_setattr_at(
        fd as i32, Some(""), 0, at_flags, uattr, size);
    if rv < 0 { close_fd(fd as i32); return rv; }
    fd
}

/// Unpublish a descriptor the syscall is not going to return. # C: O(1)
fn close_fd(fd: i32) {
    let Some(cur) = sched::live::current() else { return; };
    // SAFETY: running task on this CPU; sole writer of its own fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return; };
    let _ = fdt.clone().close(fd);
}
