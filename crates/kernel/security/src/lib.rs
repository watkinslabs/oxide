// Security crate per `27`. Owns:
//   - seccomp cBPF interpreter (`security::seccomp`)
//   - bpf(2) MAP_CREATE / PROG_LOAD admit (`security::bpf`)
//   - stacked task-priority and scheduler-policy hooks (`security::lsm`)
//
// Capability bits live on `sched::Creds` (the workspace `sched`
// crate); has_cap_for / user-NS scoping live in `crates/nscg`.
// Landlock lives in its own crate (`crates/kernel/landlock`), below `sched`,
// because the enforced domain is task state.

#![no_std]
#![feature(allocator_api)]
#![forbid(unsafe_op_in_unsafe_fn)]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;
// Hosted tests only: the bottom-half exclusion contract in `network` is pinned
// against a second OS thread, which needs `std::thread`.
#[cfg(test)]
extern crate std;

mod anon_dname;
pub mod seccomp;
pub mod bpf;
pub mod bpf_lsm;
pub mod bpf_verify;
pub mod bpf_interp;
mod bpf_layout;
pub mod socket_filter;
pub mod network;
pub mod lsm;
mod task_policy;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Perm }

pub type KResult<T> = core::result::Result<T, Error>;

/// Active LSM identities in the single framework order used by hooks and
/// `lsm_list_modules`. Capability is part of the framework's fixed-first set.
pub fn active_lsm_ids() -> alloc::vec::Vec<u64> {
    lsm_framework::registry::id_list().into_iter().map(|id| id.id).collect()
}

/// Boot-time init reporter.
/// # SAFETY: caller is the boot path; pre-init; single-CPU.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> {
    let line = core::str::from_utf8(cmdline::get()).unwrap_or("");
    let params = lsm_framework::cmdline::parse(line);
    let selinux_enabled = cmdline::parameter_value(b"selinux").is_none_or(|v| v != b"0");
    let _ = lsm_framework::registry::start(
        lsm_framework::modules::builtin(selinux_enabled),
        params.selection(lsm_framework::modules::BUILTIN_ORDER),
    );
    lsm::register_device_permission(bpf::cgroup_device_inode_permission);
    task_policy::register();
    vfs::set_device_permission_hook(lsm::device_permission);
    lsm::register_open(bpf_lsm::open_hook);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // SAFETY: hosted-test path; init has no side effects.
    #[test] fn init_ok() { unsafe { assert!(init().is_ok()); } }
}
