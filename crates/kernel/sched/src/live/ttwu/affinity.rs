use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::live::runqueue::{RqIrq, Runqueue};
use crate::Task;
use syscall::errno::Errno;
use super::cpu_target::this_cpu;
use crate::live::runqueue::global_for;

use super::cpu_target::resched_locked;

fn active_cpu_mask() -> cpu::CpuMask {
    let active = cpu::smp::online_cpumask();
    if active.is_empty() { cpu::CpuMask::of(0) } else { active }
}

impl Task {
    /// Commit a Windows or Linux user affinity request through the canonical
    /// task mask owner, preserving the deadline capacity admission rule.
    /// # C: O(N_cpus · log N)
    pub fn set_user_affinity(self: &Arc<Self>, want: cpu::CpuMask)
        -> Result<cpu::CpuMask, Errno>
    {
        let _wake = self.pi_lock.lock_irqsave::<RqIrq>();
        let allowed = crate::affinity::compose(
            self.cpuset_cpus_allowed.load(Ordering::Acquire), want,
            crate::affinity::MaskChange::UserRequest);
        if crate::deadline::live::confined_below_span(self, allowed) {
            return Err(Errno::Ebusy);
        }
        if allowed.intersect(active_cpu_mask()).is_empty() {
            return Err(Errno::Einval);
        }
        self.user_cpus_allowed.store(want, Ordering::Release);
        self.cpus_allowed.store(allowed, Ordering::Release);
        let _placement = sync::rcu_read_lock();
        relocate_for_affinity_pi_locked_with_probe(
            &|cpu| unsafe { global_for(cpu) }, self, allowed,
            &cpu::smp::is_active, &mut |_, _, _| {});
        Ok(allowed)
    }

    /// Read the effective mask after applying the active CPU set under the
    /// same task-side serialization boundary used by affinity writers.
    /// # C: O(words)
    pub fn affinity_snapshot(&self) -> cpu::CpuMask {
        let _wake = self.pi_lock.lock_irqsave::<RqIrq>();
        self.cpus_allowed.load(Ordering::Acquire).intersect(active_cpu_mask())
    }
}

/// Choose the CPU to wake `task` on (Linux `select_task_rq`): the idlest
/// online runqueue (fewest `nr_running`) among the task's allowed CPUs,
/// biased to the caller's local CPU on ties (wake-affine: a not-busier
/// local stays cache-warm). Honors `cpus_allowed` (sched_setaffinity /
/// cpuset). UP / single online CPU → that CPU.
/// # C: O(N_cpus)
pub fn select_task_rq(task: &Task) -> u32 {
    let _placement = sync::rcu_read_lock();
    // SAFETY: `global_for` is sound for any index; it yields `None` for a CPU
    // that has not completed `install_global`, which the walk skips.
    select_task_rq_with(&|c| {
        if !cpu::smp::is_active(c) { None } else {
            // SAFETY: online publication follows runqueue installation.
            unsafe { global_for(c) }
        }
    }, this_cpu(), task)
}

/// [`select_task_rq`] over an injected CPU->runqueue accessor, so the placement
/// decision is exercised by hosted tests against real `Runqueue` instances on
/// more than one CPU (`GLOBALS` only accepts writes for `this_cpu()`, which is
/// unconditionally 0 off-target). Same split `rq_locate` uses.
/// # C: O(N_cpus)
pub fn select_task_rq_with<'a, F>(get_rq: &F, local: u32, task: &Task) -> u32
where F: Fn(u32) -> Option<&'a Runqueue> {
    let allowed = task.cpus_allowed.load(Ordering::Acquire);
    let prev = task.cpu.load(Ordering::Acquire);
    if prev != u16::MAX {
        let cpu = prev as u32;
        if allowed.contains(cpu as usize) {
            if let Some(rq) = get_rq(cpu) {
                // Keep prev ONLY if it is idle (cache-warm + runs the wakee
                // immediately). If prev is busy, fall through to the idlest-CPU
                // scan so the wakee lands on an idle CPU and runs now instead of
                // queueing behind prev's current task — Linux
                // `select_idle_sibling`. An unconditional prev-return made a
                // woken sync-I/O waiter wait multi-ms with idle CPUs free.
                if rq.nr_running.load(Ordering::Acquire) == 0 { return cpu; }
            }
        }
    }
    let mut best: Option<u32> = None;
    let mut best_load = u32::MAX;
    // Visit local first so equal-load ties resolve to it (wake-affine).
    let order = core::iter::once(local)
        .chain((0..cpu::MAX_CPUS as u32).filter(move |&c| c != local));
    for cpu in order {
        if !allowed.contains(cpu as usize) { continue; }
        if let Some(rq) = get_rq(cpu) {
            let load = rq.nr_running.load(Ordering::Acquire);
            if load < best_load { best_load = load; best = Some(cpu); }
        }
    }
    if let Some(cpu) = best { return cpu; }
    // Empty effective affinity cannot strand a wake. Select the idlest active
    // installed rq without rewriting configured affinity.
    for cpu in core::iter::once(local)
        .chain((0..cpu::MAX_CPUS as u32).filter(move |&c| c != local)) {
        if let Some(rq) = get_rq(cpu) {
            let load = rq.nr_running.load(Ordering::Acquire);
            if load < best_load { best_load = load; best = Some(cpu); }
        }
    }
    best.unwrap_or(local)
}

/// Honor a changed `cpus_allowed` (sched_setaffinity / cpuset): move `task`
/// off any disallowed CPU.
///
/// A task QUEUED (on_rq, not currently running) on a now-disallowed CPU is
/// dequeued here and re-placed by `select_task_rq` — it is not executing, so
/// there is no cross-CPU race. A task RUNNING on a disallowed CPU is only
/// nudged with need_resched plus a reschedule IPI: it cannot be moved while it
/// still owns a CPU's register context. The eviction itself happens when that
/// nudge lands in `schedule()`, which parks the task and lets the incoming
/// task's `finish_task_switch` place it once `on_cpu` has cleared
/// (`live::schedule::migrate`). UP / single CPU: no-op (allowed == local).
/// # C: O(N_cpus · log N)
pub fn relocate_for_affinity(task: &Arc<Task>, allowed: cpu::CpuMask) {
    relocate_for_affinity_live(task, allowed)
}

/// Publish one source of a task affinity mask and complete its relocation
/// while holding the same task-side lock ttwu uses for CPU selection.
/// # C: O(N_cpus · log N)
pub fn update_affinity(task: &Arc<Task>, user: Option<cpu::CpuMask>, cpuset: Option<cpu::CpuMask>) {
    update_affinity_active_with(&|c| {
        // SAFETY: affinity owns TaskPi while it resolves the installed owner;
        // CPU-down retains runqueue storage through the placement grace.
        unsafe { global_for(c) }
    }, task, user, cpuset, &cpu::smp::is_active);
}

/// Injected affinity update used by hosted SMP race tests. # C: O(N_cpus)
#[cfg(test)]
pub(crate) fn update_affinity_with<'a, F>(
    get_rq: &F, task: &'a Arc<Task>, user: Option<cpu::CpuMask>, cpuset: Option<cpu::CpuMask>,
)
where F: Fn(u32) -> Option<&'a Runqueue> {
    update_affinity_active_with(get_rq, task, user, cpuset,
        &|cpu| get_rq(cpu).is_some());
}

fn update_affinity_active_with<'a, F, A>(
    get_rq: &F, task: &'a Arc<Task>, user: Option<cpu::CpuMask>,
    cpuset: Option<cpu::CpuMask>, active: &A,
)
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool {
    let wake = task.pi_lock.lock_irqsave::<RqIrq>();
    if let Some(mask) = user { task.user_cpus_allowed.store(mask, Ordering::Release); }
    if let Some(mask) = cpuset { task.cpuset_cpus_allowed.store(mask, Ordering::Release); }
    let source = if user.is_some() {
        crate::affinity::MaskChange::UserRequest
    } else {
        crate::affinity::MaskChange::CpusetUpdate
    };
    let allowed = crate::affinity::compose(
        task.cpuset_cpus_allowed.load(Ordering::Acquire),
        task.user_cpus_allowed.load(Ordering::Acquire), source,
    );
    task.cpus_allowed.store(allowed, Ordering::Release);
    let wake_generation = if task.state() == crate::TaskState::Waking
        || task.on_wake_list.load(Ordering::Acquire) {
        Some(task.wake_seq.load(Ordering::Acquire))
    } else { None };
    if wake_generation.is_none() {
        relocate_for_affinity_pi_locked_with_probe(get_rq, task, allowed,
            active, &mut |_, _, _| {});
        return;
    }
    drop(wake);
    // A deferred wake retains its selected target until this exact generation
    // commits. Effective affinity is already serialized and visible, so a
    // later writer can supersede it while this writer waits without an older
    // composition being republished afterwards.
    if let Some(generation) = wake_generation {
        while wake_generation_pending(task.wake_done.load(Ordering::Acquire), generation) {
            sync::spin_relax::relax();
        }
    }
    let _wake = task.pi_lock.lock_irqsave::<RqIrq>();
    let current = task.cpus_allowed.load(Ordering::Acquire);
    relocate_for_affinity_pi_locked_with_probe(get_rq, task, current,
        active, &mut |_, _, _| {});
}

fn wake_generation_pending(done: u64, wanted: u64) -> bool {
    (wanted.wrapping_sub(done) as i64) > 0
}

fn relocate_for_affinity_live(task: &Arc<Task>, allowed: cpu::CpuMask) {
    let _wake = task.pi_lock.lock_irqsave::<RqIrq>();
    let _placement = sync::rcu_read_lock();
    relocate_for_affinity_pi_locked_with_probe(
        &|cpu| unsafe { global_for(cpu) }, task, allowed,
        &cpu::smp::is_active, &mut |_, _, _| {});
}

/// [`relocate_for_affinity`] over an injected CPU->runqueue accessor, so the
/// relocation is exercised by hosted tests against real `Runqueue` instances
/// on more than one CPU. Same split [`select_task_rq_with`] uses, and for the
/// same reason: the un-split version reaches only the live per-CPU globals,
/// which off-target exist for CPU 0 alone — that is how the running-task half
/// of this function shipped untested.
/// # C: O(N_cpus · log N)
pub fn relocate_for_affinity_with<'a, F>(get_rq: &F, task: &'a Arc<Task>, allowed: cpu::CpuMask)
where F: Fn(u32) -> Option<&'a Runqueue> {
    let _wake = task.pi_lock.lock_irqsave::<RqIrq>();
    relocate_for_affinity_pi_locked_with_probe(get_rq, task, allowed,
        &|cpu| get_rq(cpu).is_some(), &mut |_, _, _| {});
}

#[cfg(test)]
fn relocate_for_affinity_with_probe<'a, F, A, P>(get_rq: &F, task: &'a Arc<Task>,
    allowed: cpu::CpuMask, active: &A, probe: &mut P)
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool,
      P: FnMut(super::super::migration::MovePoint, u32, &Task) {
    let _wake = task.pi_lock.lock_irqsave::<RqIrq>();
    relocate_for_affinity_pi_locked_with_probe(get_rq, task, allowed, active, probe);
}

fn relocate_for_affinity_pi_locked_with_probe<'a, F, A, P>(get_rq: &F,
    task: &'a Arc<Task>, allowed: cpu::CpuMask, active: &A, probe: &mut P)
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool,
      P: FnMut(super::super::migration::MovePoint, u32, &Task) {
    let _placement = sync::rcu_read_lock();
    let from = task.cpu.load(Ordering::Acquire) as u32;
    if allowed.contains(from as usize) && active(from) { return; }
    let preferred = select_task_rq_with(&|cpu| {
        if active(cpu) { get_rq(cpu) } else { None }
    }, from, task);
    match super::super::migration::move_queued_pi_locked_with(
        get_rq, task, Some(preferred), active, probe) {
        super::super::migration::MoveResult::Running { cpu } => resched_owner(task, cpu, get_rq),
        super::super::migration::MoveResult::Moved { to, .. } => resched_cpu(to, get_rq),
        super::super::migration::MoveResult::Unplaced { from, task } => {
            if let super::super::migration::MoveResult::Moved { to, .. } =
                super::super::migration::finish_unplaced_pi_locked_with(
                    get_rq, task, from, Some(preferred), active, probe)
            {
                resched_cpu(to, get_rq);
            }
        }
        _ => {}
    }
}

fn resched_cpu<'a, F>(cpu: u32, get_rq: &F)
where F: Fn(u32) -> Option<&'a Runqueue> {
    let Some(rq) = get_rq(cpu) else { return; };
    let _inner = rq.inner.lock_irqsave::<RqIrq>();
    resched_locked(rq);
}

fn resched_owner<'a, F>(task: &Task, cpu: u32, get_rq: &F)
where F: Fn(u32) -> Option<&'a Runqueue> {
    let Some(rq) = get_rq(cpu) else { return; };
    let _inner = rq.inner.lock_irqsave::<RqIrq>();
    let current = rq.current.load(Ordering::Acquire);
    if !current.is_null() && core::ptr::eq(current.cast_const(), core::ptr::from_ref(task)) {
        resched_locked(rq);
    }
}

#[cfg(test)]
mod hotplug_tests {
    use super::*;
    use alloc::sync::Arc;
    use core::cell::Cell;

    const SRC: u32 = 37;
    const DST: u32 = 38;
    const THIRD: u32 = 39;

    fn rq(cpu: u32) -> Runqueue {
        Runqueue::new(cpu as u16,
            Arc::new(Task::new(0xD800 + cpu, "idle", crate::SchedClass::Idle)))
    }

    #[test]
    fn affinity_destination_deactivation_reselects_before_commit() {
        let src = rq(SRC);
        let dst = rq(DST);
        let third = rq(THIRD);
        let task = Arc::new(Task::new(8201, "affinity",
            crate::SchedClass::Normal { weight: 1024 }));
        let allowed = cpu::CpuMask::from_words(&[
            (1u64 << SRC) | (1u64 << DST) | (1u64 << THIRD),
        ]);
        task.cpus_allowed.store(allowed, Ordering::Release);
        {
            let mut inner = src.inner.lock();
            assert!(inner.enqueue(Arc::clone(&task)));
            src.publish_nr_running(inner.nr_running());
        }
        let dst_active = Cell::new(true);
        let get = |cpu| match cpu {
            SRC => Some(&src), DST => Some(&dst), THIRD => Some(&third), _ => None,
        };
        relocate_for_affinity_with_probe(&get, &task, allowed,
            &|cpu| cpu == THIRD || (cpu == DST && dst_active.get()),
            &mut |point, cpu, _| {
                if point == super::super::super::migration::MovePoint::DestinationLocked
                    && cpu == DST { dst_active.set(false); }
            });

        assert_eq!(src.nr_running.load(Ordering::Acquire), 0);
        assert_eq!(dst.nr_running.load(Ordering::Acquire), 0);
        assert_eq!(third.nr_running.load(Ordering::Acquire), 1);
        assert_eq!(task.cpu.load(Ordering::Acquire), THIRD as u16);
    }

    #[test]
    fn affinity_update_skips_an_installed_but_inactive_destination() {
        let src = rq(SRC);
        let dst = rq(DST);
        let third = rq(THIRD);
        let task = Arc::new(Task::new(8204, "inactive-rq",
            crate::SchedClass::Normal { weight: 1024 }));
        task.cpus_allowed.store(cpu::CpuMask::of(SRC as usize), Ordering::Release);
        {
            let mut inner = src.inner.lock();
            assert!(inner.enqueue(Arc::clone(&task)));
            src.publish_nr_running(inner.nr_running());
        }
        let get = |cpu| match cpu {
            SRC => Some(&src), DST => Some(&dst), THIRD => Some(&third), _ => None,
        };
        let mut requested = cpu::CpuMask::of(DST as usize);
        assert!(requested.insert(THIRD as usize));
        update_affinity_active_with(&get, &task, Some(requested), None,
            &|cpu| cpu == THIRD);

        assert_eq!(src.nr_running.load(Ordering::Acquire), 0);
        assert_eq!(dst.nr_running.load(Ordering::Acquire), 0,
            "retained inactive rq accepted an affinity placement");
        assert_eq!(third.nr_running.load(Ordering::Acquire), 1);
        assert_eq!(task.cpu.load(Ordering::Acquire), THIRD as u16);
        assert!(task.cpus_allowed.load(Ordering::Acquire).contains(THIRD as usize));
    }

    #[test]
    fn affinity_publishes_before_waiting_for_exact_wake_completion() {
        let src = Arc::new(rq(SRC));
        let dst = Arc::new(rq(DST));
        let task = Arc::new(Task::new(8202, "waking-affinity",
            crate::SchedClass::Normal { weight: 1024 }));
        task.cpu.store(SRC as u16, Ordering::Release);
        task.cpus_allowed.store(cpu::CpuMask::of(SRC as usize), Ordering::Release);
        task.set_state(crate::TaskState::Sleeping);
        assert!(task.claim_wake());
        let worker_task = Arc::clone(&task);
        let worker_src = Arc::clone(&src);
        let worker_dst = Arc::clone(&dst);
        let worker = std::thread::spawn(move || {
            update_affinity_with(&|cpu| match cpu {
                SRC => Some(&*worker_src), DST => Some(&*worker_dst), _ => None,
            }, &worker_task, Some(cpu::CpuMask::of(DST as usize)), None);
        });
        while task.user_cpus_allowed.load(Ordering::Acquire)
            != cpu::CpuMask::of(DST as usize) { std::hint::spin_loop(); }
        loop {
            if let Some(stable) = task.pi_lock.try_lock() { drop(stable); break; }
            std::hint::spin_loop();
        }
        assert_eq!(task.cpus_allowed.load(Ordering::Acquire),
            cpu::CpuMask::of(DST as usize),
            "effective affinity was not serialized before the wake wait");
        task.complete_wake();
        worker.join().unwrap();
        assert_eq!(task.wake_done.load(Ordering::Acquire),
            task.wake_seq.load(Ordering::Acquire));
        assert_eq!(task.cpus_allowed.load(Ordering::Acquire),
            cpu::CpuMask::of(DST as usize));
    }

    #[test]
    fn ordered_affinity_writers_cannot_republish_a_stale_composition() {
        let src = Arc::new(rq(SRC));
        let dst = Arc::new(rq(DST));
        let third = Arc::new(rq(THIRD));
        let task = Arc::new(Task::new(8203, "affinity-writers",
            crate::SchedClass::Normal { weight: 1024 }));
        task.cpu.store(SRC as u16, Ordering::Release);
        task.cpus_allowed.store(cpu::CpuMask::of(SRC as usize), Ordering::Release);
        task.set_state(crate::TaskState::Sleeping);
        assert!(task.claim_wake());

        let first_task = Arc::clone(&task);
        let first_src = Arc::clone(&src);
        let first_dst = Arc::clone(&dst);
        let first_third = Arc::clone(&third);
        let first = std::thread::spawn(move || update_affinity_with(&|cpu| match cpu {
            SRC => Some(&*first_src), DST => Some(&*first_dst),
            THIRD => Some(&*first_third), _ => None,
        }, &first_task, Some(cpu::CpuMask::of(DST as usize)), None));
        while task.user_cpus_allowed.load(Ordering::Acquire)
            != cpu::CpuMask::of(DST as usize) { std::hint::spin_loop(); }
        loop {
            if let Some(stable) = task.pi_lock.try_lock() { drop(stable); break; }
            std::hint::spin_loop();
        }
        assert_eq!(task.cpus_allowed.load(Ordering::Acquire), cpu::CpuMask::of(DST as usize));

        let second_task = Arc::clone(&task);
        let second_src = Arc::clone(&src);
        let second_dst = Arc::clone(&dst);
        let second_third = Arc::clone(&third);
        let second = std::thread::spawn(move || update_affinity_with(&|cpu| match cpu {
            SRC => Some(&*second_src), DST => Some(&*second_dst),
            THIRD => Some(&*second_third), _ => None,
        }, &second_task, None, Some(cpu::CpuMask::of(THIRD as usize))));
        while task.cpuset_cpus_allowed.load(Ordering::Acquire)
            != cpu::CpuMask::of(THIRD as usize) { std::hint::spin_loop(); }
        loop {
            if let Some(stable) = task.pi_lock.try_lock() { drop(stable); break; }
            std::hint::spin_loop();
        }
        assert_eq!(task.cpus_allowed.load(Ordering::Acquire), cpu::CpuMask::of(THIRD as usize));

        task.complete_wake();
        first.join().unwrap();
        second.join().unwrap();
        assert_eq!(task.cpus_allowed.load(Ordering::Acquire), cpu::CpuMask::of(THIRD as usize));
        assert_eq!(task.user_cpus_allowed.load(Ordering::Acquire), cpu::CpuMask::of(DST as usize));
    }

    #[test]
    fn wake_completion_order_survives_generation_wrap() {
        assert!(wake_generation_pending(u64::MAX - 1, 1));
        assert!(!wake_generation_pending(1, u64::MAX - 1));
        assert!(!wake_generation_pending(7, 7));
    }
}
