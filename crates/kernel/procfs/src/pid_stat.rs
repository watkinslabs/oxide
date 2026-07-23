// F351: /proc/<pid>/stat body builder. Extracted from kernel procfs/mod.rs
// to keep that file under the 1000-line cap, mirroring `pid_status`.
// Field 1 (pid) and field 4 (ppid) are namespace PIDs (vtgid), NOT the
// internal kernel tid — `ps`/`top` read field 1 and must show 1 for init.

use alloc::vec::Vec;

/// # C: O(1) — fixed field set; two registry lookups for the vpids.
pub fn body(tid: u32) -> Vec<u8> {
    use core::sync::atomic::Ordering;
    let mut out = Vec::with_capacity(192);
    let task = match sched::live::registry::lookup(tid) { Some(t) => t, None => return out };
    let vpid = sched::live::registry::display_vpid(tid);
    let ppid = sched::live::registry::parent_vpid(tid);
    push_u64(&mut out, vpid);
    // `comm` (field 2): the exec'd program's basename (Linux), not the generic
    // fork-time name — `ps`/`top`/`pidof` key off this.
    let comm = task.comm();
    push(&mut out, b" ("); push(&mut out, comm.as_bytes()); push(&mut out, b") ");
    out.push(task.state().linux_char()); out.push(b' ');
    push_u64(&mut out, ppid);
    // Fields 5..52 (pgrp..). utime is field 14 → 10th of these; report the
    // task's accounted CPU time in CLK_TCK ticks (stime field 15 stays 0 —
    // v1 doesn't split user/sys). Makes the scheduler's real runtime
    // accounting observable via `ps`/`top`/`cat /proc/<pid>/stat`.
    let utime = sched::clock::ns_to_clk_tck(task.sum_exec_runtime_ns.load(Ordering::Acquire));
    let starttime = crate::proc_clock::ReaderClock::current()
        .starttime_ticks(task.start_boottime_ns);
    // mm-layout numeric fields (Linux `/proc/pid/stat`): 26 startcode,
    // 27 endcode, 28 startstack, 45 start_data, 46 end_data, 47 start_brk,
    // 48 arg_start, 49 arg_end, 50 env_start, 51 env_end. Sourced from the
    // AddressSpace bounds set at execve / rewritten by prctl(PR_SET_MM).
    // task is a foreign task (arbitrary tid): clone_mm pins against a
    // concurrent exit/execve mm replacement on another CPU.
    let mm = task.clone_mm();
    let mm_field = |f: u32| -> Option<u64> {
        let m = mm.as_ref()?;
        Some(match f {
            26 => m.start_code(),  27 => m.end_code(),   28 => m.start_stack(),
            45 => m.start_data(),  46 => m.end_data(),   47 => m.start_brk(),
            48 => m.arg_start(),   49 => m.arg_end(),    50 => m.env_start(),
            51 => m.env_end(),
            _  => return None,
        })
    };
    for f in 5u32..=52 {
        if f == 14 { push(&mut out, b" "); push_u64(&mut out, utime); }
        else if f == 22 { push(&mut out, b" "); push_u64(&mut out, starttime); }
        else if let Some(v) = mm_field(f) { push(&mut out, b" "); push_u64(&mut out, v); }
        else { push(&mut out, b" 0"); }
    }
    out.push(b'\n');
    out
}

fn push(v: &mut Vec<u8>, b: &[u8]) { v.extend_from_slice(b); }

fn push_u64(v: &mut Vec<u8>, mut n: u64) {
    if n == 0 { v.push(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; v.push(buf[i]); }
}
