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
    push(&mut out, b"prio                                         :              120\n");
    push(&mut out, b"policy                                       :                0\n");
    out
}
