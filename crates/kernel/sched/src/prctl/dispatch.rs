// `sys_prctl` fan-out — Linux `kernel/sys.c` `SYSCALL_DEFINE5(prctl)`'s
// switch. Argument validation already happened in `decide::classify`, so
// every arm here is a call into the owner of that piece of task state.

use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::decide::{self, Op};
use super::{caps, name, task_state};

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
        Op::GetTsc(p) => task_state::get_tsc(p),
        Op::SetTsc(mode) => task_state::set_tsc(mode),
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
        Op::GetTidAddress(p) => task_state::get_tid_address(&cur, p),
        Op::SetThpDisable { disable, except_advised } =>
            task_state::set_thp_disable(&cur, disable, except_advised),
        Op::GetThpDisable => task_state::get_thp_disable(&cur),
        Op::CapAmbient(a) => caps::cap_ambient(&cur, a),
        Op::GetSpecCtrl(which) => decide::spec_ctrl_get(which),
        Op::SetSpecCtrl { which, ctrl } => decide::spec_ctrl_set(which, ctrl),
        Op::SetVma => crate::prctl_vma::sys_set_vma_name(&cur, args),
    }
}
