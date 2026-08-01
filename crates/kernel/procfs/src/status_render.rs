// `/proc/<pid>/status` field rendering — Linux `fs/proc/array.c`
// (`proc_pid_status` -> `task_state` / `task_sig` / `task_cap` /
// `task_seccomp` / `task_cpus_allowed` / `cpuset_task_status_allowed` /
// `task_context_switch_counts`).
//
// Deliberately free of any target gate: the values a privileged reader acts on
// (uid/gid quads, capability bitmaps, signal sets) must be hosted-testable.
// `pid_status.rs` only COLLECTS live task state into `Status` and calls
// `render`; nothing decides anything there.

use alloc::vec::Vec;

pub(crate) mod format;
#[cfg(test)] mod tests;

use format::{push, push_dec, push_hex16, push_octal, push_cpumask, push_cpulist};

/// Everything one `/proc/<pid>/status` body needs, snapshotted from the task.
/// Every field is a real reading — there are no defaults here, precisely so a
/// caller cannot silently omit one and ship a plausible-looking constant.
pub struct Status<'a> {
    pub name:   &'a str,
    pub umask:  u32,
    pub state:  &'a str,
    pub tgid:   u64,
    /// Linux `task_numa_group_id` — 0 without NUMA balancing.
    pub ngid:   u64,
    pub pid:    u64,
    pub ppid:   u64,
    /// Linux `ptrace_parent(p)`'s pid in the reader's namespace; 0 = untraced.
    pub tracer_pid: u64,
    /// `cred->{uid, euid, suid, fsuid}` in that order (Linux prints real,
    /// effective, saved-set, filesystem).
    pub uid:    [u32; 4],
    /// `cred->{gid, egid, sgid, fsgid}`.
    pub gid:    [u32; 4],
    /// Linux `files_fdtable(p->files)->max_fds`.
    pub fd_size: u64,
    /// `cred->group_info`, ascending (the order `setgroups` stores).
    pub groups: &'a [u32],
    /// Numbers from the reader's PID namespace level inward to the task's own,
    /// one per level, the way Linux reports the whole nest.
    pub ns_tgid: &'a [u64],
    pub ns_pid:  &'a [u64],
    pub ns_pgid: &'a [u64],
    pub ns_sid:  &'a [u64],
    /// Linux `p->flags & PF_KTHREAD`.
    pub kthread: bool,
    /// Linux `get_nr_threads(p)`.
    pub threads: u64,
    /// `SigQ:\t<queued>/<RLIMIT_SIGPENDING>`.
    pub sig_queued: u64,
    pub sig_limit:  u64,
    /// `p->pending.signal`.
    pub sig_pnd: u64,
    /// `p->signal->shared_pending.signal`.
    pub shd_pnd: u64,
    /// `p->blocked`.
    pub sig_blk: u64,
    /// Signals whose `sa_handler` is `SIG_IGN` / neither `SIG_IGN` nor
    /// `SIG_DFL` (Linux `collect_sigign_sigcatch`).
    pub sig_ign: u64,
    pub sig_cgt: u64,
    pub cap_inh: u64,
    pub cap_prm: u64,
    pub cap_eff: u64,
    pub cap_bnd: u64,
    pub cap_amb: u64,
    pub no_new_privs: bool,
    /// `p->seccomp.mode` (`SECCOMP_MODE_{DISABLED,STRICT,FILTER}`).
    pub seccomp: u64,
    pub seccomp_filters: u64,
    /// `p->cpus_mask`, and how many CPU bits the mask is printed to
    /// (Linux `nr_cpu_ids`) — `%*pb` zero-pads to that width.
    pub cpus_allowed: u64,
    pub nr_cpus: u32,
    /// `p->mems_allowed` + its width (`MAX_NUMNODES`).
    pub mems_allowed: u64,
    pub nr_nodes: u32,
    pub nvcsw:  u64,
    pub nivcsw: u64,
    /// The pre-rendered `Vm*`/`Rss*` block (`crate::mem_render`). Empty for a
    /// task with no address space — Linux emits the whole block or none of it.
    pub mem_rows: &'a [u8],
}

/// Render the body in Linux's exact field order. # C: O(ngroups + nr_cpus)
pub fn render(s: &Status) -> Vec<u8> {
    let mut o = Vec::with_capacity(1024);
    push(&mut o, b"Name:\t"); push(&mut o, s.name.as_bytes());
    push(&mut o, b"\nUmask:\t"); push_octal(&mut o, s.umask as u64, 4);
    push(&mut o, b"\nState:\t"); push(&mut o, s.state.as_bytes());
    push(&mut o, b"\nTgid:\t"); push_dec(&mut o, s.tgid);
    push(&mut o, b"\nNgid:\t"); push_dec(&mut o, s.ngid);
    push(&mut o, b"\nPid:\t"); push_dec(&mut o, s.pid);
    push(&mut o, b"\nPPid:\t"); push_dec(&mut o, s.ppid);
    push(&mut o, b"\nTracerPid:\t"); push_dec(&mut o, s.tracer_pid);
    push(&mut o, b"\nUid:"); for u in s.uid { o.push(b'\t'); push_dec(&mut o, u as u64); }
    push(&mut o, b"\nGid:"); for g in s.gid { o.push(b'\t'); push_dec(&mut o, g as u64); }
    push(&mut o, b"\nFDSize:\t"); push_dec(&mut o, s.fd_size);
    // Linux emits "Groups:\t" then space-separated gids, then ALWAYS one
    // trailing space ("Trailing space shouldn't have been added in the first
    // place" — kept for compatibility, so parsers see it here too).
    push(&mut o, b"\nGroups:\t");
    for (i, g) in s.groups.iter().enumerate() {
        if i != 0 { o.push(b' '); }
        push_dec(&mut o, *g as u64);
    }
    o.push(b' ');
    push_ns_row(&mut o, b"\nNStgid:", s.ns_tgid);
    push_ns_row(&mut o, b"\nNSpid:", s.ns_pid);
    push_ns_row(&mut o, b"\nNSpgid:", s.ns_pgid);
    push_ns_row(&mut o, b"\nNSsid:", s.ns_sid);
    push(&mut o, b"\nKthread:\t"); o.push(if s.kthread { b'1' } else { b'0' });
    push(&mut o, b"\nThreads:\t"); push_dec(&mut o, s.threads);
    // Linux `proc_pid_status` emits `task_mem`'s block here, between the
    // task-state rows and the signal rows, and only when the task has an mm.
    // Every row above opens with its own '\n' and leaves none trailing, so the
    // block's own trailing newline is dropped to keep that invariant.
    if !s.mem_rows.is_empty() {
        o.push(b'\n');
        push(&mut o, s.mem_rows.strip_suffix(b"\n").unwrap_or(s.mem_rows));
    }
    push(&mut o, b"\nSigQ:\t"); push_dec(&mut o, s.sig_queued);
    o.push(b'/'); push_dec(&mut o, s.sig_limit);
    push(&mut o, b"\nSigPnd:\t"); push_hex16(&mut o, s.sig_pnd);
    push(&mut o, b"\nShdPnd:\t"); push_hex16(&mut o, s.shd_pnd);
    push(&mut o, b"\nSigBlk:\t"); push_hex16(&mut o, s.sig_blk);
    push(&mut o, b"\nSigIgn:\t"); push_hex16(&mut o, s.sig_ign);
    push(&mut o, b"\nSigCgt:\t"); push_hex16(&mut o, s.sig_cgt);
    push(&mut o, b"\nCapInh:\t"); push_hex16(&mut o, s.cap_inh);
    push(&mut o, b"\nCapPrm:\t"); push_hex16(&mut o, s.cap_prm);
    push(&mut o, b"\nCapEff:\t"); push_hex16(&mut o, s.cap_eff);
    push(&mut o, b"\nCapBnd:\t"); push_hex16(&mut o, s.cap_bnd);
    push(&mut o, b"\nCapAmb:\t"); push_hex16(&mut o, s.cap_amb);
    push(&mut o, b"\nNoNewPrivs:\t"); o.push(if s.no_new_privs { b'1' } else { b'0' });
    push(&mut o, b"\nSeccomp:\t"); push_dec(&mut o, s.seccomp);
    push(&mut o, b"\nSeccomp_filters:\t"); push_dec(&mut o, s.seccomp_filters);
    // `arch_prctl_spec_ctrl_get(PR_SPEC_STORE_BYPASS)` with no SSBD control
    // exposed, and `PR_SPEC_INDIRECT_BRANCH` likewise (Linux prints the
    // `-EINVAL` case as "unknown").
    push(&mut o, b"\nSpeculation_Store_Bypass:\tthread vulnerable");
    push(&mut o, b"\nSpeculationIndirectBranch:\tunknown");
    push(&mut o, b"\nCpus_allowed:\t"); push_cpumask(&mut o, s.cpus_allowed, s.nr_cpus);
    push(&mut o, b"\nCpus_allowed_list:\t"); push_cpulist(&mut o, s.cpus_allowed, s.nr_cpus);
    push(&mut o, b"\nMems_allowed:\t"); push_cpumask(&mut o, s.mems_allowed, s.nr_nodes);
    push(&mut o, b"\nMems_allowed_list:\t"); push_cpulist(&mut o, s.mems_allowed, s.nr_nodes);
    push(&mut o, b"\nvoluntary_ctxt_switches:\t"); push_dec(&mut o, s.nvcsw);
    push(&mut o, b"\nnonvoluntary_ctxt_switches:\t"); push_dec(&mut o, s.nivcsw);
    o.push(b'\n');
    o
}

/// One `NS*` row: the label, then one tab-prefixed number per namespace level.
/// # C: O(depth)
fn push_ns_row(o: &mut Vec<u8>, label: &[u8], numbers: &[u64]) {
    push(o, label);
    for nr in numbers { o.push(b'\t'); push_dec(o, *nr); }
}
