// The persona half of `execve`: Linux's `SET_PERSONALITY2` /
// `elf_read_implies_exec` (`fs/binfmt_elf.c:1016-1018`) and the
// `MMAP_PAGE_ZERO` emulation at the tail of `load_elf_binary` (`:1349-1361`).
//
// Both arches this kernel targets are 64-bit-only, which fixes both halves of
// the READ_IMPLIES_EXEC decision:
//   * `SET_PERSONALITY` CLEARS `READ_IMPLIES_EXEC` on x86_64
//     (`set_personality_64bit`) and on arm64 alike, so a caller cannot arm it
//     and have the next image inherit it;
//   * `elf_read_implies_exec` never SETS it — x86 gates on `mmap_is_ia32()`,
//     and arm64 defines only the `compat_` form, leaving the generic
//     `#define elf_read_implies_exec(ex, stk) 0`. The `PT_GNU_STACK`-absent
//     "exec-all" row of the arch tables belongs to the 32-bit columns only.
// Neither arch resets the execution-domain byte at exec: both override the
// generic `SET_PERSONALITY` macro that would have folded it back to PER_LINUX.

#![cfg(target_os = "oxide-kernel")]

use vmm::AddressSpace;

/// Linux `SET_PERSONALITY(ex)` for a 64-bit native image. Runs at the same
/// point the credential transition commits, so a failed `execve` leaves the
/// caller's persona untouched.
/// # C: O(1)
pub(crate) fn set_personality(cur: &sched::Task) {
    sched::personality::clear(cur, sched::personality::PER_CLEAR_ON_EXEC);
}

/// Linux `arch_setup_new_exec()` plus `reset_thread_features()` — the
/// per-thread arch state a fresh image must NOT inherit.
///
/// `TIF_NOCPUID`: "If cpuid was previously disabled for this task, re-enable
/// it." A caller must not be able to hand a setuid image a `cpuid` that
/// faults, which would make its CPU-feature dispatch take an unexpected
/// branch or die on an unhandled #GP. The live MSR is reprogrammed here, not
/// left to the next context switch, because the exec returns to user before
/// any switch is guaranteed to happen.
///
/// `thread.features` / `thread.features_locked`: the CET facility set and its
/// lock. Carrying a lock across exec would make the new program's first
/// `ARCH_SHSTK_ENABLE` a permanent EPERM for reasons it cannot see.
/// # C: O(1)
pub(crate) fn arch_setup_new_exec(cur: &sched::Task) {
    use core::sync::atomic::Ordering;
    if cur.nocpuid.swap(crate::arch_prctl_abi::cpuid::nocpuid_after_exec(), Ordering::AcqRel) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: runs on the CPU whose MSR is being reprogrammed, inside the
        // exec commit with preemption disabled by the caller's scope; a no-op
        // on a CPU with no CPUID-faulting mechanism.
        unsafe { hal_x86_64::set_cpuid_faulting(false); }
    }
    let reset = crate::arch_prctl_abi::shstk::ShstkState::after_exec();
    cur.shstk_features.store(reset.features, Ordering::Release);
    cur.shstk_locked.store(reset.locked, Ordering::Release);
}

/// Linux `load_elf_binary`'s SVR4 emulation, dispatched to its owner.
///
/// `per_clear` is the exec's `bprm->per_clear`, which carries `MMAP_PAGE_ZERO`
/// for a privileged image — a caller must not be able to pre-arm a readable
/// page 0 under a setuid binary. Linux applies it in `begin_new_exec`, before
/// this test; this kernel commits credentials later, so it is folded in here
/// exactly as `exec_transition::exec_rnd` folds it into the ASLR decision.
/// # C: O(log N_vmas)
pub(crate) fn map_page_zero(cur: &sched::Task, new_as: &AddressSpace, per_clear: u32) {
    let persona = sched::personality::at_exec(sched::personality::get(cur), per_clear);
    if !sched::personality::mmap_page_zero(persona) { return; }
    elf_load::persona::map_page_zero(new_as);
}
