// `syscall_rollback(task, regs)` — what a SKIPPED syscall leaves in the
// return register.
//
// Both `seccomp`'s `SECCOMP_RET_TRAP` and syscall user dispatch roll the call
// back before raising a catchable `SIGSYS`, so a handler that returns resumes
// with the register set the trap left. The rolled-back value is
// ARCHITECTURE-SPECIFIC and the two arches do NOT agree:
//
//   x86_64   `regs->ax = regs->orig_ax` — the syscall NUMBER, because x86
//            stages the number in the same register the return value uses.
//   aarch64  `regs->regs[0] = regs->orig_x0` — the FIRST ARGUMENT, because
//            the number lives in `x8` and `x0` only ever held `arg0`.
//
// Returning the number on both, as this did, meant an aarch64 SIGSYS handler
// that returned saw the syscall number where its ABI says `arg0` is — so a
// userspace dispatcher or a seccomp-trap handler that inspects or forwards
// the original arguments read the wrong one, silently and only on ARM.
//
// Ungated on purpose: the consumers are kernel-target-only files where a
// `#[cfg(test)]` block compiles away in silence.

/// The value a rolled-back syscall leaves in the return register.
/// # C: O(1)
pub fn rolled_back_return(nr: u64, a0: u64) -> u64 {
    if cfg!(target_arch = "aarch64") { a0 } else { nr }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole content of this module: the two arches disagree, and the
    /// disagreement is the ABI's.
    #[test]
    fn rollback_restores_the_register_the_arch_clobbered() {
        let (nr, a0) = (0x9e, 0xdead_beef);
        let want = if cfg!(target_arch = "aarch64") { a0 } else { nr };
        assert_eq!(rolled_back_return(nr, a0), want);
    }

    /// A zero first argument must still come through as zero on aarch64 —
    /// falling back to the syscall number for a "missing-looking" value would
    /// reintroduce the bug for the commonest case of all.
    #[test]
    fn a_zero_first_argument_is_not_replaced_by_the_number() {
        assert_eq!(rolled_back_return(60, 0),
                   if cfg!(target_arch = "aarch64") { 0 } else { 60 });
    }
}
