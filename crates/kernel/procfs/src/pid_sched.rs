// `/proc/<pid>/sched` body. Split from procfs/mod.rs for the 1000-line
// cap (`08§7`). Reports the scheduler's real CPU-time accounting
// (`13§3`): se.exec_start / se.vruntime / se.sum_exec_runtime now carry
// live values from `Task` rather than static zeros.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use crate::live::{push, push_u64};

/// # C: O(1) registry lookup
pub(crate) fn pid_sched_body(tid: u32) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(128);
    let task = match sched::live::registry::lookup(tid) { Some(t) => t, None => return out };
    push(&mut out, task.comm().as_bytes());
    push(&mut out, b" (");
    // Linux `/proc/<pid>/sched` shows the pid AS SEEN IN THE READER'S PID NS
    // (the visible pid), NOT the opaque internal tid. systemd's detect_container
    // parses this field for PID 1 and, if it is not `1`, concludes it is inside
    // a PID namespace → reports the VM as `container-other`, which skips
    // ConditionVirtualization=!container units and breaks the gdm graphical
    // greeter. Emit the visible pid (vtgid) so PID 1 reads `systemd (1, …)`.
    push_u64(&mut out, sched::live::registry::display_vpid(tid));
    push(&mut out, b", #threads: 1)\n");
    push(&mut out, b"-------------------------------------------------------------------\n");
    push(&mut out, b"se.exec_start                                : ");
    push_u64(&mut out, task.exec_start_ns.load(Ordering::Acquire)); out.push(b'\n');
    push(&mut out, b"se.vruntime                                  : ");
    push_u64(&mut out, task.vruntime.load(Ordering::Acquire)); out.push(b'\n');
    push(&mut out, b"se.sum_exec_runtime                          : ");
    push_u64(&mut out, task.sum_exec_runtime_ns.load(Ordering::Acquire) / 1_000_000); out.push(b'\n');
    push(&mut out, b"nr_switches                                  :                0\n");
    // Linux renders `p->prio` (RT: 99 - rt_priority; fair: 120 + nice) and
    // `p->policy`. Sourced from the task, never hardcoded — `chrt` changes
    // must be visible here.
    push(&mut out, b"prio                                         : ");
    push_u64(&mut out, task_prio(&task)); out.push(b'\n');
    push(&mut out, b"policy                                       : ");
    push_u64(&mut out, task.policy.load(Ordering::Acquire) as u64); out.push(b'\n');
    out
}

/// Linux `task_prio()`: RT tasks land in `0..=98` (`MAX_RT_PRIO-1 - rt_prio`),
/// fair tasks in `100 + nice + 20` (`MAX_RT_PRIO + NICE_WIDTH/2` at nice 0).
/// # C: O(1)
fn task_prio(task: &sched::Task) -> u64 {
    /// Linux `MAX_RT_PRIO`.
    const MAX_RT_PRIO: i32 = 100;
    /// Linux `DEFAULT_PRIO` = `MAX_RT_PRIO + NICE_WIDTH / 2`.
    const DEFAULT_PRIO: i32 = MAX_RT_PRIO + 20;
    match task.sched_class() {
        sched::SchedClass::Rt { prio, .. } => (MAX_RT_PRIO - 1 - prio as i32) as u64,
        _ => (DEFAULT_PRIO + task.nice.load(Ordering::Acquire) as i32) as u64,
    }
}
