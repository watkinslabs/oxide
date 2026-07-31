// `/proc/<pid>/status` value COLLECTION. Every field is read from the owning
// subsystem's live state (`sched::Task` + its `Creds`, `ThreadGroup`,
// `SigActions`, fd table); the rendering lives in `crate::status_render`, which
// carries no target gate and is where the hosted tests run. Nothing here
// decides anything, so nothing here can be a phantom test.
//
// Before B1463 this file printed `Uid:\t0\t0\t0\t0` and
// `CapPrm/CapEff/CapBnd = 000001ffffffffff` for EVERY task, plus a constant
// NoNewPrivs/Threads/SigQ/Sig*/Seccomp block. systemd, polkit, dbus-daemon and
// pkexec read exactly those lines to decide who a peer is.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::status_render::{render, Status};

/// Signals 1..=64 whose action is `SIG_IGN`, and those with a real handler
/// (Linux `collect_sigign_sigcatch`). # C: O(64)
fn sigign_sigcatch(task: &sched::Task) -> (u64, u64) {
    const NSIG: u32 = 64;
    let (mut ign, mut cgt) = (0u64, 0u64);
    let actions = task.sigactions_ref();
    for sig in 1..=NSIG {
        let act = actions.get(sig);
        let bit = 1u64 << (sig - 1);
        if act.is_ignored() { ign |= bit; }
        else if act.is_caught() { cgt |= bit; }
    }
    (ign, cgt)
}

/// Linux `files_fdtable(p->files)->max_fds`. # C: O(1)
fn fd_size(task: &sched::Task) -> u64 {
    // SAFETY: read-only capacity probe of the task's fd table; `fd_table_ref`
    // hands back the live table and `capacity` takes that table's own lock.
    match unsafe { task.fd_table_ref() } { Some(t) => t.capacity() as u64, None => 0 }
}

/// # C: O(ngroups + 64 signal slots)
pub fn body(tid: u32) -> Vec<u8> {
    let Some(task) = sched::live::registry::lookup(tid) else { return Vec::new() };
    // Display the namespace PID (Linux "PID" == our vtgid), not the internal
    // kernel tid. PID1 (systemd/init) is stamped vtgid=1 but keeps an opaque
    // internal tid; `ps` reads these fields and must show 1, not 0xC0DE….
    let vpid = sched::live::registry::display_vpid(tid);
    let ppid = sched::live::registry::parent_vpid(tid);
    let c = &task.creds;
    let group_list = c.group_list();
    let groups: &[u32] = group_list.as_deref().unwrap_or(&[]);
    let (sig_ign, sig_cgt) = sigign_sigcatch(&task);
    // Linux `/proc/pid/status`: `SigPnd` is the THREAD-private set and `ShdPnd`
    // the process-wide one (`signal_struct::shared_pending`), which this kernel
    // keeps on the `ThreadGroup`.
    let shd_pnd = task.thread_group.shared_pending();
    let tracer = task.traced_by.load(Ordering::Acquire);
    let name = task.comm();
    let mem_rows = crate::pid_mem::status_rows(&task);
    let s = Status {
        name:   &name,
        umask:  task.umask(),
        state:  task.state().linux_status_label(),
        tgid:   vpid,
        // Linux `task_numa_group_id` — no NUMA balancing, so no group.
        ngid:   0,
        pid:    vpid,
        ppid,
        tracer_pid: if tracer == 0 { 0 } else { sched::live::registry::display_vpid(tracer) },
        uid: [c.ruid.load(Ordering::Acquire), c.euid.load(Ordering::Acquire),
              c.suid.load(Ordering::Acquire), c.fsuid.load(Ordering::Acquire)],
        gid: [c.rgid.load(Ordering::Acquire), c.egid.load(Ordering::Acquire),
              c.sgid.load(Ordering::Acquire), c.fsgid.load(Ordering::Acquire)],
        fd_size: fd_size(&task),
        groups,
        ns_tgid: vpid,
        ns_pid:  vpid,
        ns_pgid: task.pgid() as u64,
        ns_sid:  task.sid() as u64,
        // Linux `PF_KTHREAD`. A kernel thread is exactly a task with no mm,
        // which is also the property `task_dump_owner` uses the flag to detect.
        kthread: task.clone_mm().is_none(),
        threads: sched::live::registry::thread_entries(task.tgid.load(Ordering::Acquire)).len() as u64,
        // No per-user queued-signal accounting exists to source a non-zero
        // `qsize` from; the limit is the task's real RLIMIT_SIGPENDING.
        sig_queued: 0,
        sig_limit:  task.rlimit(sched::rlimit::rlim::SIGPENDING).0,
        sig_pnd: task.sigpending.load(Ordering::Acquire),
        shd_pnd,
        sig_blk: task.sigmask.load(Ordering::Acquire),
        sig_ign,
        sig_cgt,
        cap_inh: c.cap_inheritable.load(Ordering::Acquire),
        cap_prm: c.cap_permitted.load(Ordering::Acquire),
        cap_eff: c.cap_effective.load(Ordering::Acquire),
        cap_bnd: c.cap_bounding.load(Ordering::Acquire),
        cap_amb: c.cap_ambient.load(Ordering::Acquire),
        no_new_privs: task.no_new_privs.load(Ordering::Acquire),
        seccomp: task.seccomp_mode.load(Ordering::Acquire) as u64,
        seccomp_filters: task.seccomp_filter_count() as u64,
        cpus_allowed: task.cpus_allowed.load(Ordering::Acquire),
        // Linux `nr_cpu_ids` — the width `%*pb` pads the mask to.
        nr_cpus: (cpu::smp::online_count() as u32).clamp(1, cpu::MAX_CPUS as u32),
        // One NUMA node.
        mems_allowed: 1,
        nr_nodes: 1,
        nvcsw:  task.nvcsw.load(Ordering::Relaxed),
        nivcsw: task.nivcsw.load(Ordering::Relaxed),
        mem_rows: &mem_rows,
    };
    render(&s)
}
