// `sys_prctl` fan-out — Linux `kernel/sys.c` `SYSCALL_DEFINE5(prctl)`'s
// switch. Argument validation already happened in `decide::classify`, so
// every arm here is a call into the owner of that piece of task state.

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::decide::{self, Op};
use super::{apply, arm64, caps, futex_hash, name, rseq_slice, task_state};

/// `sys_prctl(option, arg2, arg3, arg4, arg5)` — slot 157.
///
/// `PR_SET_SECCOMP` is the one option this function cannot own: seccomp lives
/// in the `security` crate, which depends on `sched`. The slot file routes it
/// the way Linux routes `security_task_prctl` — before this switch — and
/// hands the rest here.
/// # C: O(1) except PR_SET_CHILD_SUBREAPER (O(N_descendants)) and
/// PR_SET_MM/PR_SET_VMA (O(blob) / O(K log N))
pub fn sys_prctl(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let op = match decide::classify(args.a0, args.a1, args.a2, args.a3, args.a4) {
        Ok(op) => op,
        Err(e) => return -(e.as_i32() as i64),
    };
    match op {
        Op::SetPdeathsig(sig) => task_state::set_pdeathsig(&cur, sig),
        Op::GetPdeathsig(p) => task_state::get_pdeathsig(&cur, p),
        Op::GetDumpable => cur.dumpable.load(core::sync::atomic::Ordering::Acquire) as i64,
        Op::SetDumpable(v) => name::set_dumpable(&cur, v),
        Op::GetKeepcaps => caps::get_keepcaps(&cur),
        Op::SetKeepcaps(on) => caps::set_keepcaps(&cur, on),
        // Linux hard-codes both: `PR_GET_TIMING` answers PR_TIMING_STATISTICAL
        // and `PR_SET_TIMING` accepts only that same value. There is no other
        // timing mode in any Linux since 2.6.
        Op::GetTiming => super::uapi::PR_TIMING_STATISTICAL as i64,
        Op::SetTiming => 0,
        Op::SetName(_) => name::sys_set_name(&cur, args),
        Op::GetName(_) => name::sys_get_name(&cur, args),
        Op::GetSeccomp => caps::get_seccomp(&cur),
        // Routed by the slot file before this switch; unreachable here.
        Op::SetSeccomp { .. } => -(Errno::Einval.as_i32() as i64),
        Op::CapbsetRead(cap) => caps::capbset_read(&cur, cap),
        Op::CapbsetDrop(cap) => caps::capbset_drop(&cur, cap),
        Op::GetTsc(p) => task_state::get_tsc(&cur, p),
        Op::SetTsc(mode) => task_state::set_tsc(&cur, mode),
        Op::GetSecurebits => caps::get_securebits(&cur),
        Op::SetSecurebits(v) => caps::set_securebits(&cur, v),
        Op::SetTimerslack(ns) => task_state::set_timerslack(&cur, ns),
        Op::GetTimerslack => task_state::get_timerslack(&cur),
        // `perf_event_task_{disable,enable}()` walk this task's own perf-event
        // list and return 0. This port creates no perf events, so the walk is
        // empty and 0 is the same answer Linux gives — not a stubbed success.
        Op::PerfEventsDisable | Op::PerfEventsEnable => 0,
        Op::MceKillClear => task_state::mce_kill_clear(&cur),
        Op::MceKillSet(policy) => task_state::mce_kill_set(&cur, policy),
        Op::MceKillGet => task_state::mce_kill_get(&cur),
        Op::SetMm => crate::prctl_set_mm::sys_set_mm(&cur, args),
        Op::SetChildSubreaper(on) => task_state::set_child_subreaper(&cur, on),
        Op::GetChildSubreaper(p) => task_state::get_child_subreaper(&cur, p),
        Op::SetNoNewPrivs => task_state::set_no_new_privs(&cur),
        Op::GetNoNewPrivs => task_state::get_no_new_privs(&cur),
        // Yama records the relation against the caller's THREAD GROUP LEADER:
        // the exemption is process-level, and a thread that sets it must not
        // create a relation only its own tid satisfies.
        Op::ClearPtracer => { crate::yama::ptracer_del(cur.tgid.load(Ordering::Acquire)); 0 }
        Op::SetPtracer(tracer) => {
            let tracee = cur.tgid.load(Ordering::Acquire);
            match tracer {
                None => { crate::yama::ptracer_add(tracee, None); 0 }
                // `find_get_task_by_vpid(arg2)`: an unknown pid is EINVAL.
                Some(vpid) => match crate::registry::lookup_by_vpid(vpid) {
                    Some(t) => {
                        crate::yama::ptracer_add(tracee, Some(t.tgid.load(Ordering::Acquire)));
                        0
                    }
                    None => -(Errno::Einval.as_i32() as i64),
                },
            }
        }
        Op::GetTidAddress(p) => task_state::get_tid_address(&cur, p),
        Op::SetThpDisable { disable, except_advised } =>
            task_state::set_thp_disable(&cur, disable, except_advised),
        Op::GetThpDisable => task_state::get_thp_disable(&cur),
        Op::CapAmbient(a) => caps::cap_ambient(&cur, a),
        Op::GetSpecCtrl(which) => decide::spec_ctrl_get(which),
        Op::SetSpecCtrl { which, ctrl } => decide::spec_ctrl_set(which, ctrl),
        Op::SetMdwe(request) => {
            // SAFETY: syscall dispatch holds the current task's mm slot stable.
            let Some(mm) = (unsafe { cur.mm_ref() }) else {
                return -(Errno::Einval.as_i32() as i64);
            };
            match mm.mdwe_set(request) {
                Ok(()) => 0,
                Err(vmm::MdweSetError::Immutable) =>
                    -(Errno::Eperm.as_i32() as i64),
            }
        }
        Op::GetMdwe => {
            // SAFETY: syscall dispatch holds the current task's mm slot stable.
            let Some(mm) = (unsafe { cur.mm_ref() }) else {
                return -(Errno::Einval.as_i32() as i64);
            };
            match mm.mdwe_get() {
                vmm::MdweRequest::Disabled => 0,
                vmm::MdweRequest::RefuseExecGain =>
                    super::uapi::PR_MDWE_REFUSE_EXEC_GAIN as i64,
                vmm::MdweRequest::RefuseExecGainNoInherit =>
                    (super::uapi::PR_MDWE_REFUSE_EXEC_GAIN
                        | super::uapi::PR_MDWE_NO_INHERIT) as i64,
            }
        }
        Op::SetVma => crate::prctl_vma::sys_set_vma_name(&cur, args),
        Op::SetIoFlusher { a2, a3, a4, a5 } => apply::set_io_flusher(&cur, a2, a3, a4, a5),
        Op::GetIoFlusher { a2, a3, a4, a5 } => apply::get_io_flusher(&cur, a2, a3, a4, a5),
        Op::SetSyscallUserDispatch(cfg) => apply::set_syscall_user_dispatch(&cur, &cfg),
        Op::GetAuxv { ptr, len } => apply::get_auxv(&cur, ptr, len),
        Op::TimerCreateRestoreIds(op) => apply::timer_create_restore_ids(&cur, op),
        // The arm64-only group. `arm64::features()` reads this CPU's
        // `ID_AA64*_EL1` registers (all-zero on any other target), so the
        // answer is the hardware's, not a compile-time assumption.
        Op::SveGetVl | Op::SveSetVl(_) | Op::SmeGetVl | Op::SmeSetVl(_) => {
            // `sve_set_current_vl` / `sme_set_current_vl` test support before
            // touching `arg`, so an unsupported system answers EINVAL for
            // every argument including a well-formed one.
            let f = arm64::features();
            let ok = match op {
                Op::SveGetVl | Op::SveSetVl(_) => arm64::sve_available(f),
                _ => arm64::sme_available(f),
            };
            if ok { 0 } else { -(Errno::Einval.as_i32() as i64) }
        }
        Op::PacResetKeys(arg) => match arm64::pac_reset_keys_check(arm64::features(), arg) {
            // Reachable only once this kernel owns the per-task keys; the
            // regeneration hangs off this arm at that point.
            Ok(()) => 0,
            Err(e) => -(e.as_i32() as i64),
        },
        Op::PacSetEnabledKeys { keys, enabled } =>
            match arm64::pac_set_enabled_keys_check(arm64::features(), keys, enabled) {
                Ok(()) => 0,
                Err(e) => -(e.as_i32() as i64),
            },
        Op::PacGetEnabledKeys => {
            if arm64::address_auth_available(arm64::features()) { 0 }
            else { -(Errno::Einval.as_i32() as i64) }
        }
        Op::SetTaggedAddrCtrl(arg) => match arm64::tagged_addr_set_check(arm64::features(), arg) {
            Ok(on) => { cur.tagged_addr.store(on, Ordering::Release); 0 }
            Err(e) => -(e.as_i32() as i64),
        },
        Op::GetTaggedAddrCtrl =>
            match arm64::tagged_addr_get(cur.tagged_addr.load(Ordering::Acquire)) {
                Ok(v) => v,
                Err(e) => -(e.as_i32() as i64),
            },
        Op::FutexHash { cmd, slots, a4 } => futex_hash::decide(cmd, slots, a4),
        Op::RseqSliceExtension { cmd, ctrl, a4, a5 } => {
            let request = match rseq_slice::decide(cmd, ctrl, a4, a5) {
                Ok(request) => request,
                Err(e) => return -(e.as_i32() as i64),
            };
            #[cfg(target_os = "oxide-kernel")]
            { crate::rseq::slice_extension_prctl(&cur, request) }
            #[cfg(not(target_os = "oxide-kernel"))]
            { let _ = (cur, request); 0 }
        }
    }
}
