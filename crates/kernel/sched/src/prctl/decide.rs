// `prctl(2)` option classification + per-option argument rules — Linux
// `kernel/sys.c` `SYSCALL_DEFINE5(prctl)` and the helpers it dispatches to
// (`prctl_set_thp_disable`, `prctl_set_mm`, `security/commoncap.c`
// `cap_task_prctl`).
//
// Pure decision logic, no `Task` and no user memory, so every argument rule
// is reachable from `cargo test`. Linux rejects non-zero arg3/arg4/arg5 for
// most options and silently ignores them for a handful; getting that split
// wrong is invisible until a hardened runtime passes garbage tail args and
// gets a success it should not have.

use syscall::errno::Errno;

use super::uapi::*;

/// `PR_CAP_AMBIENT` sub-command after `cap_valid` has been applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ambient { ClearAll, IsSet(u32), Raise(u32), Lower(u32) }

/// One resolved `prctl` option. Variants carry arguments that passed boundary
/// validation, except `CapbsetDrop`: its raw capability stays intact so the
/// capability owner can apply Linux's permission-before-validity ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    SetPdeathsig(u32),
    GetPdeathsig(u64),
    GetDumpable,
    SetDumpable(u8),
    GetKeepcaps,
    SetKeepcaps(bool),
    GetTiming,
    SetTiming,
    SetName(u64),
    GetName(u64),
    GetSeccomp,
    SetSeccomp { mode: u64, filter: u64 },
    CapbsetRead(u32),
    CapbsetDrop(u64),
    GetTsc(u64),
    SetTsc(u32),
    GetSecurebits,
    SetSecurebits(u64),
    SetTimerslack(u64),
    GetTimerslack,
    PerfEventsDisable,
    PerfEventsEnable,
    MceKillClear,
    MceKillSet(u64),
    MceKillGet,
    SetMm,
    SetChildSubreaper(bool),
    GetChildSubreaper(u64),
    SetNoNewPrivs,
    GetNoNewPrivs,
    /// `PR_SET_PTRACER`. `None` is `PR_SET_PTRACER_ANY`; the zero form is
    /// classified as `ClearPtracer` instead.
    SetPtracer(Option<u32>),
    ClearPtracer,
    GetTidAddress(u64),
    SetThpDisable { disable: bool, except_advised: bool },
    GetThpDisable,
    CapAmbient(Ambient),
    GetSpecCtrl(u64),
    SetSpecCtrl { which: u64, ctrl: u64 },
    SetMdwe(vmm::MdweRequest),
    GetMdwe,
    SetVma,
    /// `PR_SET_IO_FLUSHER` / `PR_GET_IO_FLUSHER` carry their raw arguments:
    /// the CAP_SYS_RESOURCE test runs BEFORE argument validation, so the
    /// ladder cannot be split across `classify` (which has no credentials).
    SetIoFlusher { a2: u64, a3: u64, a4: u64, a5: u64 },
    GetIoFlusher { a2: u64, a3: u64, a4: u64, a5: u64 },
    SetSyscallUserDispatch(super::sud::Config),
    GetAuxv { ptr: u64, len: u64 },
    TimerCreateRestoreIds(super::timer_ids::RestoreIds),
    FutexHash { cmd: u64, slots: u64, a4: u64 },
    RseqSliceExtension { cmd: u64, ctrl: u64, a4: u64, a5: u64 },
}

/// Linux `if (arg2 || arg3 || arg4 || arg5) return -EINVAL;` and its shorter
/// tail variants. # C: O(N_args)
fn none_of(args: &[u64]) -> Result<(), Errno> {
    if args.iter().any(|a| *a != 0) { Err(Errno::Einval) } else { Ok(()) }
}

/// Linux `valid_signal(sig)` — `sig <= _NSIG`, evaluated on the FULL
/// `unsigned long`. Truncating to `u32` first would accept
/// `PR_SET_PDEATHSIG, 0x1_0000_0009` as SIGKILL-adjacent garbage.
/// # C: O(1)
fn valid_signal(sig: u64) -> bool { sig <= NSIG }

/// Linux `cap_valid(x)` — `x <= CAP_LAST_CAP`. # C: O(1)
fn cap_valid(cap: u64) -> bool { cap <= CAP_LAST_CAP }

/// Resolve one `prctl(option, arg2, arg3, arg4, arg5)` call to the operation
/// it names, or to the errno Linux answers before touching any state.
///
/// Unknown options are EINVAL (`kernel/sys.c` default arm). Options this port
/// does not implement are NOT listed here, so they take the same EINVAL path —
/// see the per-option notes in `prctl.rs` for which of those are Linux gaps.
/// # C: O(1)
pub fn classify(option: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<Op, Errno> {
    match option {
        // Linux checks only `valid_signal(arg2)`; arg3..arg5 are ignored.
        PR_SET_PDEATHSIG => {
            if !valid_signal(a2) { return Err(Errno::Einval); }
            Ok(Op::SetPdeathsig(a2 as u32))
        }
        PR_GET_PDEATHSIG => Ok(Op::GetPdeathsig(a2)),
        PR_GET_DUMPABLE => Ok(Op::GetDumpable),
        // Linux accepts ONLY 0 and 1 here. `SUID_DUMP_ROOT` (2) is a state the
        // kernel enters by itself on a privilege change; userspace may read it
        // back via PR_GET_DUMPABLE but may never request it.
        PR_SET_DUMPABLE => {
            if a2 != crate::task::SUID_DUMP_DISABLE as u64
                && a2 != crate::task::SUID_DUMP_USER as u64 {
                return Err(Errno::Einval);
            }
            Ok(Op::SetDumpable(a2 as u8))
        }
        PR_GET_KEEPCAPS => Ok(Op::GetKeepcaps),
        PR_SET_KEEPCAPS => {
            if a2 > 1 { return Err(Errno::Einval); }
            Ok(Op::SetKeepcaps(a2 != 0))
        }
        PR_GET_TIMING => Ok(Op::GetTiming),
        PR_SET_TIMING => {
            if a2 != PR_TIMING_STATISTICAL { return Err(Errno::Einval); }
            Ok(Op::SetTiming)
        }
        PR_SET_NAME => Ok(Op::SetName(a2)),
        PR_GET_NAME => Ok(Op::GetName(a2)),
        PR_GET_SECCOMP => Ok(Op::GetSeccomp),
        PR_SET_SECCOMP => Ok(Op::SetSeccomp { mode: a2, filter: a3 }),
        PR_CAPBSET_READ => {
            if !cap_valid(a2) { return Err(Errno::Einval); }
            Ok(Op::CapbsetRead(a2 as u32))
        }
        PR_CAPBSET_DROP => {
            Ok(Op::CapbsetDrop(a2))
        }
        // GET_TSC writes an `unsigned int` through arg2 and returns 0/-EFAULT;
        // it does NOT return the mode as the syscall value.
        PR_GET_TSC => Ok(Op::GetTsc(a2)),
        PR_SET_TSC => {
            if a2 != PR_TSC_ENABLE as u64 && a2 != PR_TSC_SIGSEGV as u64 {
                return Err(Errno::Einval);
            }
            Ok(Op::SetTsc(a2 as u32))
        }
        PR_GET_SECUREBITS => Ok(Op::GetSecurebits),
        PR_SET_SECUREBITS => Ok(Op::SetSecurebits(a2)),
        PR_SET_TIMERSLACK => Ok(Op::SetTimerslack(a2)),
        PR_GET_TIMERSLACK => Ok(Op::GetTimerslack),
        PR_TASK_PERF_EVENTS_DISABLE => Ok(Op::PerfEventsDisable),
        PR_TASK_PERF_EVENTS_ENABLE => Ok(Op::PerfEventsEnable),
        PR_MCE_KILL => {
            none_of(&[a4, a5])?;
            match a2 {
                PR_MCE_KILL_CLEAR => { none_of(&[a3])?; Ok(Op::MceKillClear) }
                PR_MCE_KILL_SET => match a3 {
                    PR_MCE_KILL_EARLY | PR_MCE_KILL_LATE | PR_MCE_KILL_DEFAULT =>
                        Ok(Op::MceKillSet(a3)),
                    _ => Err(Errno::Einval),
                },
                _ => Err(Errno::Einval),
            }
        }
        PR_MCE_KILL_GET => { none_of(&[a2, a3, a4, a5])?; Ok(Op::MceKillGet) }
        // `prctl_set_mm` validates its own sub-command; the shared tail rule
        // is arg5 == 0 and arg4 == 0 except for AUXV / MAP / MAP_SIZE.
        PR_SET_MM => {
            if a5 != 0 { return Err(Errno::Einval); }
            const AUXV: u64 = vmm::PR_SET_MM_AUXV as u64;
            const MAP: u64 = vmm::PR_SET_MM_MAP as u64;
            const MAP_SIZE: u64 = vmm::PR_SET_MM_MAP_SIZE as u64;
            if a4 != 0 && !matches!(a2, AUXV | MAP | MAP_SIZE) { return Err(Errno::Einval); }
            Ok(Op::SetMm)
        }
        PR_SET_CHILD_SUBREAPER => Ok(Op::SetChildSubreaper(a2 != 0)),
        PR_GET_CHILD_SUBREAPER => Ok(Op::GetChildSubreaper(a2)),
        PR_SET_NO_NEW_PRIVS => {
            if a2 != 1 { return Err(Errno::Einval); }
            none_of(&[a3, a4, a5])?;
            Ok(Op::SetNoNewPrivs)
        }
        PR_GET_NO_NEW_PRIVS => { none_of(&[a2, a3, a4, a5])?; Ok(Op::GetNoNewPrivs) }
        // Yama `yama_task_prctl`: 0 removes the relation, `PR_SET_PTRACER_ANY`
        // (and the truncated `(int)arg2 == -1` spelling) names every process,
        // anything else names one vpid. The remaining arguments are unused and
        // Yama does not inspect them.
        PR_SET_PTRACER => {
            if a2 == 0 { return Ok(Op::ClearPtracer); }
            if a2 == PR_SET_PTRACER_ANY || a2 as i32 == -1 { return Ok(Op::SetPtracer(None)); }
            Ok(Op::SetPtracer(Some(a2 as u32)))
        }
        PR_GET_TID_ADDRESS => Ok(Op::GetTidAddress(a2)),
        PR_SET_THP_DISABLE => {
            none_of(&[a4, a5])?;
            let disable = a2 != 0;
            // Flags are only allowed when disabling, and EXCEPT_ADVISED is
            // the only defined one.
            if (!disable && a3 != 0) || (a3 & !PR_THP_DISABLE_EXCEPT_ADVISED) != 0 {
                return Err(Errno::Einval);
            }
            Ok(Op::SetThpDisable { disable, except_advised: a3 & PR_THP_DISABLE_EXCEPT_ADVISED != 0 })
        }
        PR_GET_THP_DISABLE => { none_of(&[a2, a3, a4, a5])?; Ok(Op::GetThpDisable) }
        // Linux: "No longer implemented" — an explicit EINVAL arm, not the
        // unknown-option default.
        PR_MPX_ENABLE_MANAGEMENT | PR_MPX_DISABLE_MANAGEMENT => Err(Errno::Einval),
        PR_CAP_AMBIENT => {
            if a2 == PR_CAP_AMBIENT_CLEAR_ALL {
                none_of(&[a3, a4, a5])?;
                return Ok(Op::CapAmbient(Ambient::ClearAll));
            }
            // Linux: `if (((!cap_valid(arg3)) | arg4 | arg5)) return -EINVAL;`
            // runs BEFORE the sub-command is recognised, so a bad cap number
            // beats an unknown sub-command.
            if !cap_valid(a3) || a4 != 0 || a5 != 0 { return Err(Errno::Einval); }
            let cap = a3 as u32;
            match a2 {
                PR_CAP_AMBIENT_IS_SET => Ok(Op::CapAmbient(Ambient::IsSet(cap))),
                PR_CAP_AMBIENT_RAISE => Ok(Op::CapAmbient(Ambient::Raise(cap))),
                PR_CAP_AMBIENT_LOWER => Ok(Op::CapAmbient(Ambient::Lower(cap))),
                _ => Err(Errno::Einval),
            }
        }
        PR_GET_SPECULATION_CTRL => { none_of(&[a3, a4, a5])?; Ok(Op::GetSpecCtrl(a2)) }
        PR_SET_SPECULATION_CTRL => {
            none_of(&[a4, a5])?;
            Ok(Op::SetSpecCtrl { which: a2, ctrl: a3 })
        }
        PR_SET_MDWE => {
            none_of(&[a3, a4, a5])?;
            let request = match a2 {
                0 => vmm::MdweRequest::Disabled,
                PR_MDWE_REFUSE_EXEC_GAIN => vmm::MdweRequest::RefuseExecGain,
                bits if bits == PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT =>
                    vmm::MdweRequest::RefuseExecGainNoInherit,
                _ => return Err(Errno::Einval),
            };
            Ok(Op::SetMdwe(request))
        }
        PR_GET_MDWE => { none_of(&[a2, a3, a4, a5])?; Ok(Op::GetMdwe) }
        PR_SET_VMA => Ok(Op::SetVma),
        // The IO-flusher pair keeps its raw arguments: Linux tests
        // CAP_SYS_RESOURCE first and only then the arguments, so an
        // unprivileged caller gets EPERM even for a malformed call.
        PR_SET_IO_FLUSHER => Ok(Op::SetIoFlusher { a2, a3, a4, a5 }),
        PR_GET_IO_FLUSHER => Ok(Op::GetIoFlusher { a2, a3, a4, a5 }),
        // `set_syscall_user_dispatch(arg2, arg3, arg4, arg5)` — no tail rule
        // in the switch; the mode arm owns every argument.
        PR_SET_SYSCALL_USER_DISPATCH =>
            super::sud::classify_set(a2, a3, a4, a5).map(Op::SetSyscallUserDispatch),
        PR_GET_AUXV => {
            super::auxv::validate_tail(a4, a5)?;
            Ok(Op::GetAuxv { ptr: a2, len: a3 })
        }
        PR_TIMER_CREATE_RESTORE_IDS => {
            none_of(&[a3, a4, a5])?;
            super::timer_ids::classify(a2).map(Op::TimerCreateRestoreIds)
        }
        // `futex_hash_prctl(arg2, arg3, arg4)` — arg5 is not read at all.
        PR_FUTEX_HASH => Ok(Op::FutexHash { cmd: a2, slots: a3, a4 }),
        PR_RSEQ_SLICE_EXTENSION => Ok(Op::RseqSliceExtension { cmd: a2, ctrl: a3, a4, a5 }),
        _ => Err(Errno::Einval),
    }
}

/// Linux `prctl_get_thp_disable` return encoding: 0 when THP is not disabled,
/// `1` for COMPLETELY, `1 | PR_THP_DISABLE_EXCEPT_ADVISED` for the softer
/// mode. # C: O(1)
pub fn thp_disable_report(state: u8) -> i64 {
    match state {
        crate::task::THP_DISABLE_COMPLETELY => 1,
        crate::task::THP_DISABLE_EXCEPT_ADVISED => 1 | PR_THP_DISABLE_EXCEPT_ADVISED as i64,
        _ => 0,
    }
}

/// Linux `PR_MCE_KILL_GET`: `PF_MCE_PROCESS` ? (`PF_MCE_EARLY` ? EARLY : LATE)
/// : DEFAULT. # C: O(1)
pub fn mce_kill_report(flags: u8) -> i64 {
    if flags & crate::task::MCE_KILL_PROCESS == 0 { return PR_MCE_KILL_DEFAULT as i64; }
    if flags & crate::task::MCE_KILL_EARLY != 0 { PR_MCE_KILL_EARLY as i64 }
    else { PR_MCE_KILL_LATE as i64 }
}

/// Linux `PR_MCE_KILL_SET` policy → the `PF_MCE_*` pair it installs. # C: O(1)
pub fn mce_kill_apply(policy: u64) -> u8 {
    match policy {
        PR_MCE_KILL_EARLY => crate::task::MCE_KILL_PROCESS | crate::task::MCE_KILL_EARLY,
        PR_MCE_KILL_LATE => crate::task::MCE_KILL_PROCESS,
        // PR_MCE_KILL_DEFAULT clears BOTH bits, including PF_MCE_PROCESS that
        // the enclosing `PR_MCE_KILL_SET` arm had just set.
        _ => 0,
    }
}

/// `arch_prctl_spec_ctrl_get` for a kernel that compiles in no speculative-
/// execution mitigation and exposes no per-task control.
///
/// With `ssb_mode == SPEC_STORE_BYPASS_NONE` and
/// `spectre_v2_user_{ibpb,stibp} == SPECTRE_V2_USER_NONE`, Linux answers
/// `PR_SPEC_ENABLE` for both — speculation is on and unrestricted. Answering
/// `PR_SPEC_NOT_AFFECTED` instead would be a safety claim about the CPU this
/// port never makes. `PR_SPEC_L1D_FLUSH` matches `l1d_flush_prctl_get`'s
/// `!switch_mm_cond_l1d_flush` arm, `PR_SPEC_FORCE_DISABLE`. Any other
/// `which` is ENODEV.
/// # C: O(1)
pub fn spec_ctrl_get(which: u64) -> i64 {
    match which {
        PR_SPEC_STORE_BYPASS | PR_SPEC_INDIRECT_BRANCH => PR_SPEC_ENABLE,
        PR_SPEC_L1D_FLUSH => PR_SPEC_FORCE_DISABLE,
        _ => -(Errno::Enodev.as_i32() as i64),
    }
}

/// `arch_prctl_spec_ctrl_set` for the same configuration.
///
/// `ssb_prctl_set` gates on `ssb_mode` being PRCTL/SECCOMP and answers
/// **ENXIO** otherwise — not EINVAL, not EPERM. `ib_prctl_set` with both
/// spectre-v2 user modes NONE accepts `PR_SPEC_ENABLE` (returns 0, nothing to
/// do) and answers EPERM for DISABLE/FORCE_DISABLE, with ERANGE for any other
/// `ctrl`. `l1d_flush_prctl_set` answers EPERM when the conditional flush is
/// not armed. Unknown `which` is ENODEV.
/// # C: O(1)
pub fn spec_ctrl_set(which: u64, ctrl: u64) -> i64 {
    let err = |e: Errno| -(e.as_i32() as i64);
    match which {
        PR_SPEC_STORE_BYPASS => err(Errno::Enxio),
        PR_SPEC_INDIRECT_BRANCH => match ctrl as i64 {
            PR_SPEC_ENABLE => 0,
            PR_SPEC_DISABLE | PR_SPEC_FORCE_DISABLE => err(Errno::Eperm),
            _ => err(Errno::Erange),
        },
        PR_SPEC_L1D_FLUSH => err(Errno::Eperm),
        _ => err(Errno::Enodev),
    }
}

#[cfg(test)]
#[path = "decide/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "decide/tests_options.rs"]
mod tests_options;
