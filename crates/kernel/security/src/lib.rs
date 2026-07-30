// Security crate per `27`. Owns:
//   - seccomp cBPF interpreter (`security::seccomp`)
//   - bpf(2) MAP_CREATE / PROG_LOAD admit (`security::bpf`)
//
// Capability bits live on `sched::Creds` (the workspace `sched`
// crate); has_cap_for / user-NS scoping live in `crates/nscg`.
// Landlock admit + file-cap (security.capability xattr) live in
// kernel-side glue files because they wire directly into the
// syscall dispatch + xattr storage paths.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;

mod anon_dname;
pub mod seccomp;
pub mod bpf;
pub mod bpf_lsm;
pub mod bpf_verify;
pub mod bpf_interp;
mod bpf_layout;
pub mod socket_filter;
pub mod network;
#[cfg(any(target_os = "oxide-kernel", test))]
pub mod landlock;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Perm }

pub type KResult<T> = core::result::Result<T, Error>;

/// Boot-time init reporter.
/// # SAFETY: caller is the boot path; pre-init; single-CPU.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> {
    vfs::set_device_permission_hook(bpf::cgroup_device_inode_permission);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // SAFETY: hosted-test path; init has no side effects.
    #[test] fn init_ok() { unsafe { assert!(init().is_ok()); } }
}
