// `sys_prctl` (slot 157) — module manifest.
//
// Linux `kernel/sys.c` `SYSCALL_DEFINE5(prctl)` plus the helpers it fans out
// to. Split per `08§7` / crate-shape rules:
//
//   uapi        — `PR_*` option numbers and sub-values (`include/uapi/linux/prctl.h`)
//   arm64       — the arm64-only options (tagged-address ABI, SVE/SME vector
//                 length, pointer auth), each gated on a real ID-register read
//   tsc         — PR_{SET,GET}_TSC: the per-task counter-read trap and the
//                 context-switch re-assert that keeps it true
//   decide      — option classification + per-option argument rules; ungated,
//                 so `cargo test` reaches every validation rule
//   dispatch    — the `Op` -> owner fan-out (`sys_prctl` itself)
//   name        — PR_SET_NAME / PR_GET_NAME / PR_SET_DUMPABLE
//   task_state  — per-task state options (pdeathsig, subreaper, no-new-privs,
//                 timerslack, THP, MCE, tid-address)
//   caps        — capability-set options (`security/commoncap.c` `cap_task_prctl`)
//   sud         — PR_SET_SYSCALL_USER_DISPATCH: registration + the per-syscall
//                 predicate the dispatch head consumes
//   io_flusher  — PR_{SET,GET}_IO_FLUSHER, incl. the live no-IO-reclaim flag
//   auxv        — PR_GET_AUXV truncation / return-size rule
//   timer_ids   — PR_TIMER_CREATE_RESTORE_IDS + timer_create's id rule
//   futex_hash  — PR_FUTEX_HASH
//   rseq_slice  — PR_RSEQ_SLICE_EXTENSION
//
// `prctl_set_mm` and `prctl_vma` stay in their own sibling modules.
//
// OPTIONS THAT ANSWER EINVAL, and why each is Linux's own answer here:
//   * PR_{GET,SET}_UNALIGN/FPEMU/FPEXC/ENDIAN, PR_{SET,GET}_FP_MODE — the
//     generic `(-EINVAL)` macros; no architecture this port targets overrides
//     them (unaligned-access control is alpha/parisc/powerpc/riscv/sh, FP
//     emulation and exception control and endianness are powerpc, FP_MODE is
//     MIPS). Listed EXPLICITLY in `decide::classify` with tests, so the answer
//     is a decision rather than the unknown-option default.
//   * PR_SVE_*, PR_SME_*, PR_PAC_* — `prctl/arm64` gates each on the real
//     `ID_AA64*_EL1` read AND on whether this kernel manages the per-task
//     state it implies. The FPU save area is FPSIMD-only and there are no
//     per-task pointer-auth keys, so they are EINVAL — the answer a Linux
//     built without that support gives, and the only honest one.
//   * PR_SCHED_CORE, PR_{SET,GET}_MEMORY_MERGE — CONFIG-gated off in Linux
//     too; the option is absent from the switch and lands on EINVAL.
//   * PR_RISCV_*, PR_PPC_* — other architectures.
//   * PR_{GET,SET,LOCK}_SHADOW_STACK_STATUS, PR_GET_CFI/PR_SET_CFI — no CET
//     user shadow stack / branch-landing-pad support compiled in.
//
// PR_{SET,GET}_TAGGED_ADDR_CTRL is implemented for real on aarch64:
// `TCR_EL1.TBI0` is set at boot, and `uaccess::access_ok` untags before its
// range check, so the flag is consumed rather than merely stored. x86_64 has
// no equivalent translation-regime control and answers EINVAL, as Linux does.
//
// PR_{SET,GET}_TSC carries a per-task counter-read trap through the context
// switch on BOTH arches (`prctl::tsc`): `CR4.TSD` on x86_64,
// `CNTKCTL_EL1.EL0{P,V}CTEN` on aarch64.

pub mod uapi;
pub mod decide;
pub mod arm64;
pub mod sud;
pub mod io_flusher;
pub mod auxv;
pub mod timer_ids;
mod futex_hash;
pub(crate) mod rseq_slice;
// The fan-out and its live-task glue need `crate::live`, which is itself
// build-gated; every DECISION module above stays ungated so `cargo test`
// reaches it, and so `Task` can name the two live state types on any target.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))] mod apply;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))] mod dispatch;
mod name;
mod task_state;
pub mod tsc;
mod caps;

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub use dispatch::sys_prctl;
pub use name::{sys_get_name, sys_set_dumpable, sys_set_name};
pub use uapi::{PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, PR_SET_KEEPCAPS, PR_SET_SECUREBITS};
