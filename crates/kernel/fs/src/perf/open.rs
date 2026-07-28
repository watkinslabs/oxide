// `perf_event_open(2)` — Linux `kernel/events/core.c`
// `SYSCALL_DEFINE5(perf_event_open, ...)`.
//
// The decision ladder is a pure function (`admit`) so its errno ORDER is
// hosted-testable; only fd allocation and the target-task lookup touch live
// kernel state.

use syscall::errno::Errno;

use super::attr::{allow_cpu, allow_kernel, PerfAttr};
use super::counter::{sw_source, SwSource};
use super::uapi::{attr_bit, clockid, open_flags, ptype, sample};

/// Inputs the pure admission ladder needs from live kernel state.
#[derive(Clone, Copy, Debug)]
pub struct OpenCtx {
    pub paranoid:    i32,
    pub perfmon:     bool,
    /// `ns_capable(CAP_KILL)` on the target's user namespace — only consulted
    /// for `attr.sigtrap`.
    pub cap_kill:    bool,
    pub nr_cpus:     u32,
    /// `find_lively_task_by_vpid(pid)` succeeded (`pid != -1`).
    pub task_found:  bool,
    /// `ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)` on the target.
    pub may_access:  bool,
    /// `group_fd != -1` and it referred to a real perf file.
    pub group: Option<GroupCtx>,
}

/// The group leader's attributes, when `group_fd != -1`.
#[derive(Clone, Copy, Debug)]
pub struct GroupCtx {
    pub leader_inherit: bool,
    /// The leader is itself a group member (`group_leader->group_leader != leader`).
    pub leader_is_sibling: bool,
    pub leader_tid: Option<u32>,
    pub leader_cpu: i32,
}

/// What a successful admission produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub source:  SwSource,
    pub cloexec: bool,
    /// Join the leader's group rather than becoming a leader.
    pub join_group: bool,
}

/// The whole `perf_event_open` decision ladder, in Linux's order.
///
/// `attr` must already have gone through `attr::parse_attr` (that call is where
/// `-E2BIG`/`-EFAULT`/the branch-stack `-EACCES` come from). `pid`/`cpu`/
/// `group_fd`/`flags` are the raw syscall arguments.
/// # C: O(1)
pub fn admit(attr: &PerfAttr, pid: i32, cpu: i32, group_fd: i32, flags: u64, ctx: &OpenCtx)
    -> Result<Admitted, Errno>
{
    if flags & !open_flags::ALL != 0 { return Err(Errno::Einval); }

    // `security_perf_event_open(PERF_SECURITY_OPEN)` — no LSM in oxide.
    if !attr.bit(attr_bit::EXCLUDE_KERNEL) && !allow_kernel(ctx.paranoid, ctx.perfmon) {
        return Err(Errno::Eacces);
    }
    if attr.bit(attr_bit::NAMESPACES) && !ctx.perfmon { return Err(Errno::Eacces); }

    if attr.freq() {
        // `attr.sample_freq` aliases `sample_period` in the same union.
        if attr.sample_period > sample_rate_ceiling(ctx) { return Err(Errno::Einval); }
    } else if attr.sample_period & (1 << 63) != 0 {
        return Err(Errno::Einval);
    }

    if attr.sample_type & sample::PHYS_ADDR != 0 && !allow_kernel(ctx.paranoid, ctx.perfmon) {
        return Err(Errno::Eacces);
    }
    // `security_locked_down(LOCKDOWN_PERF)` for PERF_SAMPLE_REGS_INTR — oxide
    // has no lockdown LSM, so it is a no-op, as on a lockdown-less Linux.

    if flags & open_flags::PID_CGROUP != 0 {
        if pid == -1 || cpu == -1 { return Err(Errno::Einval); }
        // `perf_cgroup_connect()` with `!CONFIG_CGROUP_PERF` is `-EINVAL`;
        // oxide builds no perf cgroup controller.
        return Err(Errno::Einval);
    }

    let cloexec = flags & open_flags::FD_CLOEXEC != 0;

    // Linux allocates the fd here, then validates group_fd, then the pid.
    let join_group = match (group_fd, ctx.group) {
        (-1, _)       => false,
        (_, None)     => return Err(Errno::Ebadf),
        (_, Some(_))  => flags & open_flags::FD_NO_GROUP == 0,
    };

    if pid != -1 && !ctx.task_found { return Err(Errno::Esrch); }
    let has_task = pid != -1;

    if has_task && join_group {
        let g = ctx.group.expect("join_group implies a leader");
        if g.leader_inherit != attr.bit(attr_bit::INHERIT) { return Err(Errno::Einval); }
    }

    // `perf_event_alloc()`: a CPU-context event must name a real CPU, and
    // `sigtrap` needs a task to signal.
    if cpu < 0 || cpu as u32 >= ctx.nr_cpus {
        if !has_task || cpu != -1 { return Err(Errno::Einval); }
    }
    if attr.bit(attr_bit::SIGTRAP) && !has_task { return Err(Errno::Einval); }

    // `perf_init_event()`: oxide registers the software PMUs only. Every other
    // `perf_type_id` (and every unknown type) falls through `idr_find` and the
    // pmu list to `-ENOENT`, exactly as on a Linux whose CPU PMU driver never
    // registered — a guest with no architectural PMU, no kprobe/uprobe
    // tracepoint PMU and no hardware breakpoint slots.
    if attr.ty != ptype::SOFTWARE { return Err(Errno::Enoent); }
    let source = sw_source(attr.config).ok_or(Errno::Enoent)?;

    // `perf_try_init_event`: software PMUs set `PERF_PMU_CAP_NO_NMI`, so all
    // five clock ids are legal, but nothing else is.
    if attr.bit(attr_bit::USE_CLOCKID) && !clock_ok(attr.clockid) { return Err(Errno::Einval); }
    // `perf_swevent_init`: "no branch sampling for software events".
    if attr.sample_type & sample::BRANCH_STACK != 0 { return Err(Errno::Eopnotsupp); }

    // `find_get_context()` + the `!task` arm's CPU-online test collapse to the
    // paranoid gate for a CPU-wide event.
    if !has_task && !allow_cpu(ctx.paranoid, ctx.perfmon) { return Err(Errno::Eacces); }

    if has_task && !perf_check_permission(attr, ctx) { return Err(Errno::Eacces); }

    if join_group {
        let g = ctx.group.expect("join_group implies a leader");
        // "Do not allow a recursive hierarchy": the leader must be a leader.
        if g.leader_is_sibling { return Err(Errno::Einval); }
        // Software events co-schedule freely, but the group must still share a
        // context: same task and same CPU.
        let want_tid = if has_task { Some(pid as u32) } else { None };
        if g.leader_tid != want_tid || g.leader_cpu != cpu { return Err(Errno::Einval); }
    }

    Ok(Admitted { source, cloexec, join_group })
}

/// `perf_check_permission()` (`kernel/events/core.c`). # C: O(1)
fn perf_check_permission(attr: &PerfAttr, ctx: &OpenCtx) -> bool {
    let mut is_capable = ctx.perfmon;
    if attr.bit(attr_bit::SIGTRAP) { is_capable &= ctx.cap_kill; }
    is_capable || ctx.may_access
}

fn sample_rate_ceiling(ctx: &OpenCtx) -> u64 {
    let _ = ctx;
    sched::perf_sw::sample_rate().max(0) as u64
}

/// `perf_event_set_clock()`'s accepted `clockid_t` set. # C: O(1)
pub fn clock_ok(id: i32) -> bool {
    matches!(id, clockid::REALTIME | clockid::MONOTONIC | clockid::MONOTONIC_RAW
                 | clockid::BOOTTIME | clockid::TAI)
}
