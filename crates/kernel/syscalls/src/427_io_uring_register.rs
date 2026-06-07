// sys_io_uring_register (NR_IO_URING_REGISTER=427) per docs/53§0 —
// per-syscall-file module. v1: silent 0 (no fixed-buffer / file
// registration). All ring machinery stays in the io_uring module.

#![cfg(target_os = "oxide-kernel")]

/// `sys_io_uring_register(fd, op, arg, nr_args)` — slot 427.
/// v1: silent 0 (no fixed-buffer / file registration).
/// # C: O(1)
pub fn sys_io_uring_register(_args: &syscall::SyscallArgs) -> i64 { 0 }
