// `sys_prctl` (slot 157) — module manifest.
//
// Linux `kernel/sys.c` `SYSCALL_DEFINE5(prctl)` plus the helpers it fans out
// to. Split per `08§7` / crate-shape rules:
//
//   uapi        — `PR_*` option numbers and sub-values (`include/uapi/linux/prctl.h`)
//   decide      — option classification + per-option argument rules; ungated,
//                 so `cargo test` reaches every validation rule
//   dispatch    — the `Op` -> owner fan-out (`sys_prctl` itself)
//   name        — PR_SET_NAME / PR_GET_NAME / PR_SET_DUMPABLE
//   task_state  — per-task state options (pdeathsig, subreaper, no-new-privs,
//                 timerslack, THP, MCE, TSC, tid-address)
//   caps        — capability-set options (`security/commoncap.c` `cap_task_prctl`)
//
// `prctl_set_mm` and `prctl_vma` stay in their own sibling modules.
//
// OPTIONS THIS PORT DOES NOT IMPLEMENT fall through `decide::classify` to
// EINVAL, which is Linux's own answer for most of them on x86_64/aarch64:
//   * PR_{GET,SET}_UNALIGN/FPEMU/FPEXC/ENDIAN, PR_{SET,GET}_FP_MODE —
//     `SET_UNALIGN_CTL` and friends are `(-EINVAL)` macros on both arches.
//   * PR_SVE_*, PR_SME_*, PR_PAC_* — arm64 answers EINVAL without the
//     corresponding CPU feature, which this port does not expose.
//   * PR_SCHED_CORE, PR_{SET,GET}_MEMORY_MERGE — CONFIG-gated off in Linux
//     too; the option is absent from the switch and lands on EINVAL.
//   * PR_SET_PTRACER — Yama LSM only; without Yama, Linux's
//     `security_task_prctl` returns -ENOSYS and the switch answers EINVAL.
//   * PR_RISCV_*, PR_PPC_* — other architectures.
//   * PR_{GET,SET,LOCK}_SHADOW_STACK_STATUS, PR_GET_CFI/PR_SET_CFI — no CET
//     user shadow stack / branch-landing-pad support compiled in.
// These are Linux-matching refusals. The genuinely MISSING ones — options
// Linux implements on x86_64/aarch64 that this port answers EINVAL for — are
// PR_{SET,GET}_IO_FLUSHER, PR_SET_SYSCALL_USER_DISPATCH, PR_{SET,GET}_MDWE,
// PR_GET_AUXV, PR_TIMER_CREATE_RESTORE_IDS, PR_FUTEX_HASH,
// PR_RSEQ_SLICE_EXTENSION and PR_{SET,GET}_TAGGED_ADDR_CTRL (aarch64 TBI).

pub mod uapi;
pub mod decide;
mod dispatch;
mod name;
mod task_state;
mod caps;

pub use dispatch::sys_prctl;
pub use name::{sys_get_name, sys_set_dumpable, sys_set_name};
pub use uapi::{PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, PR_SET_KEEPCAPS, PR_SET_SECUREBITS};
