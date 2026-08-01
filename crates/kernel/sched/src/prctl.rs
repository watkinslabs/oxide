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
// OPTIONS THIS PORT DOES NOT IMPLEMENT fall through `decide::classify` to
// EINVAL, which is Linux's own answer for each of them on x86_64/aarch64:
//   * PR_{GET,SET}_UNALIGN/FPEMU/FPEXC/ENDIAN, PR_{SET,GET}_FP_MODE — the
//     generic `(-EINVAL)` macros; no architecture this port targets overrides
//     them (FP_MODE is MIPS-only).
//   * PR_SVE_*, PR_SME_*, PR_PAC_*, PR_{SET,GET}_TAGGED_ADDR_CTRL — arm64
//     answers EINVAL without SVE/SME/pointer-auth/the tagged-address ABI.
//     This port exposes none of them: TCR_EL1 is programmed with TBI off, so
//     accepting PR_SET_TAGGED_ADDR_CTRL would promise a top-byte-ignore
//     hardware behaviour the MMU is not configured for.
//   * PR_SCHED_CORE, PR_{SET,GET}_MEMORY_MERGE — CONFIG-gated off in Linux
//     too; the option is absent from the switch and lands on EINVAL.
//   * PR_RISCV_*, PR_PPC_* — other architectures.
//   * PR_{GET,SET,LOCK}_SHADOW_STACK_STATUS, PR_GET_CFI/PR_SET_CFI — no CET
//     user shadow stack / branch-landing-pad support compiled in.
//
// PR_SET_TSC is the one option that accepts a strict subset of Linux's
// values: PR_TSC_SIGSEGV needs a per-task CR4.TSD toggle carried through
// context switch, which is a HAL entry-path change (`docs/54`), not a
// syscall-ABI one. See `task_state::set_tsc`.

pub mod uapi;
pub mod decide;
pub mod arm64;
pub mod sud;
pub mod io_flusher;
pub mod auxv;
pub mod timer_ids;
mod futex_hash;
mod rseq_slice;
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
