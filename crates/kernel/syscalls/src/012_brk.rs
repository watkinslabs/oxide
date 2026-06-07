// 012 brk — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// sys_brk — adjust brk within ELF heap VMA. F158: enforces
/// RLIMIT_DATA per Linux semantic.
/// # C: O(log N_vmas)
pub fn sys_brk(args: &SyscallArgs) -> i64 {
    let req = args.a0;
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    // SAFETY: running task, no concurrent mm writer per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return 0 };
    if req == 0 { return mm.brk() as i64; }
    // SAFETY: rlimits single-mutator per `13§5`.
    let rlim_data = unsafe { (*cur.rlimits.get())[sched::rlimit::rlim::DATA].0 };
    let cur_brk = mm.brk();
    if rlim_data != sched::rlimit::INFINITY
        && req > cur_brk && req - cur_brk > rlim_data {
        return cur_brk as i64;
    }
    // cgroup v2 memory.max enforcement: charge the committed delta to the
    // process's cgroup. A growing brk that would exceed an ancestor
    // memory.max fails (Linux returns the old brk); a shrink uncharges.
    use core::sync::atomic::Ordering;
    let pid = cur.tgid.load(Ordering::Acquire) as u64;
    if req > cur_brk {
        if !cgroup::try_charge(pid, req - cur_brk) { return cur_brk as i64; }
        let out = mm.try_set_brk(req);
        if out < req { cgroup::uncharge(pid, req - out); } // partial/failed grow
        out as i64
    } else if req < cur_brk {
        let out = mm.try_set_brk(req);
        if out < cur_brk { cgroup::uncharge(pid, cur_brk - out); }
        out as i64
    } else {
        mm.try_set_brk(req) as i64
    }
}
