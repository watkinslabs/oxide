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

extern crate alloc;

pub mod seccomp;
pub mod bpf;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Perm }

pub type KResult<T> = core::result::Result<T, Error>;

/// Boot-time init reporter.
/// # SAFETY: caller is the boot path; pre-init; single-CPU.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    // SAFETY: hosted-test path; init has no side effects.
    #[test] fn init_ok() { unsafe { assert!(init().is_ok()); } }
}
