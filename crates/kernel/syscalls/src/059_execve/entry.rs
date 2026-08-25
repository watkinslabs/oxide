#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use syscall::SyscallArgs;

use crate::execve_common::read_user_exec_path;

use super::x86_64::execve_inner;

/// `sys_execve(path, argv, envp)` per `15§5` / `31§4`. This is the ABI entry
/// shim: it owns user-path import and hands the owned path to the x86 exec
/// transaction.
/// # SAFETY: syscall process context, IRQs enabled.
/// # C: O(64) + execve_inner cost
pub fn sys_execve(args: &SyscallArgs) -> i64 {
    let path_owned = match read_user_exec_path(args.a0) {
        Ok(v) => v,
        Err(rc) => return rc,
    };
    #[cfg(feature = "debug-swap")]
    trace_swap_exec(&path_owned);
    execve_inner(args, path_owned)
}

/// Retained, feature-gated trace for the userspace half of swap activation.
/// # C: O(path length)
#[cfg(feature = "debug-swap")]
fn trace_swap_exec(path: &[u8]) {
    if matches!(path, b"/sbin/swapon" | b"/usr/sbin/swapon" | b"/usr/bin/swapon") {
        klog::write_raw(b"[SWAPON] exec ");
        klog::write_raw(path);
        klog::write_raw(b"\n");
    }
}

/// Retained, feature-gated `execve` stage trace for the swap activator.
/// # C: O(path length)
#[cfg(feature = "debug-swap")]
pub(super) fn trace_swap_exec_stage(path: &[u8], stage: &[u8]) {
    if matches!(path, b"/sbin/swapon" | b"/usr/sbin/swapon" | b"/usr/bin/swapon") {
        klog::write_raw(b"[SWAPON] exec-stage ");
        klog::write_raw(stage);
        klog::write_raw(b"\n");
    }
}
