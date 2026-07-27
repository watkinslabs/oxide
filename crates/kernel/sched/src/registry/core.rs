// Shared registry storage + arch IRQ gate. Owns the `Registry` struct
// (tid-keyed truth + vpid accelerator hint) and the mechanics every
// other registry submodule locks through. No public API surface here
// beyond what siblings need via `super::`.

use alloc::collections::BTreeMap;
use alloc::sync::Weak;
use sync::{Spinlock, TaskList as TaskListClass};

use crate::Task;

/// Arch IRQ gate for `REG`. Hosted builds have no interrupts to mask.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub(crate) type RegIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub(crate) type RegIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) type RegIrq = sync::NoopIrq;

/// tid → Task (Linux pid-hash / idr equivalent): O(log N) point lookup,
/// authoritative for every tid that has ever been `insert`ed and not yet
/// pruned. Every entry is unique and immutable-keyed (tid is assigned once,
/// never reused while live).
///
/// `vpid_hint` is NEVER a second source of truth: it is a best-effort
/// vpid(vtgid) → thread-group-leader cache, populated at `insert` and
/// re-validated against the canonical `Task::{vtgid,vtid,reaped}` fields on
/// every read before being trusted (`vpid.rs`). A stale or absent hint always
/// falls back to the authoritative `by_tid` scan, so the hint can go stale
/// (thread-group churn, `unshare(CLONE_NEWPID)` rebinding vtgid — F153/
/// `272_unshare.rs`, which does not update this cache) without ever
/// producing a wrong answer — only a slower one for that vpid until the next
/// insert or successful lookup re-heals it.
pub(super) struct Registry {
    pub(super) by_tid:    BTreeMap<u32, Weak<Task>>,
    pub(super) vpid_hint: BTreeMap<u32, Weak<Task>>,
}

impl Registry {
    const fn new() -> Self {
        Self { by_tid: BTreeMap::new(), vpid_hint: BTreeMap::new() }
    }
}

/// The task registry (Linux `tasklist_lock`).
///
/// Taken with IRQs masked at EVERY site, because a hard-IRQ handler reaches it:
/// the UART RX ISR delivers `^C` through `KernelFgSignal::raise` ->
/// `tasks_in_pgrp`, which walks this map (`06§3.1`, `skizm.md` 3.1 #6 / Step
/// 4d). A process-context holder that could be interrupted there would be
/// spun on forever by its own CPU. Linux takes the `tasklist_lock` read side
/// with `read_lock_irqsave` for exactly the paths IRQ context reads — same
/// reasoning applies here to every acquisition site, not just the IRQ one:
/// one lock shared by an IRQ-reachable caller means every acquisition must be
/// IRQ-safe, or a process-context holder self-deadlocks its own CPU.
///
/// B1429: was a flat `Vec<(u32, Weak<Task>)>` scanned O(N) per lookup; now a
/// `BTreeMap` so point lookups (`tid.rs::lookup`, `wait.rs::parent_tgid_locked`)
/// are O(log N) instead of O(N) under this IRQs-off lock.
pub(super) static REG: Spinlock<Registry, TaskListClass> = Spinlock::new(Registry::new());

/// Insert-or-refresh the vpid accelerator hint for `task`. Threads sharing a
/// vpid (CLONE_THREAD) are common — a hint always prefers the thread-group
/// LEADER (`vtid == vtgid`) over a member, matching `vpid.rs::lookup_by_vpid`'s
/// own precedence, and only overwrites a non-leader hint if the existing
/// entry is confirmed dead (never demotes a live leader hint to a member).
/// # C: O(log N)
pub(super) fn hint_upsert(map: &mut BTreeMap<u32, Weak<Task>>, task: &Task, weak: Weak<Task>) {
    use core::sync::atomic::Ordering;
    let vpid = task.vtgid.load(Ordering::Acquire);
    if vpid == 0 { return; } // kthreads / pre-namespace tasks carry no vpid
    if task.vtid.load(Ordering::Acquire) == vpid {
        map.insert(vpid, weak);
        return;
    }
    match map.get(&vpid) {
        Some(existing) if existing.strong_count() > 0 => {} // keep the live candidate
        _ => { map.insert(vpid, weak); }
    }
}

/// Drop confirmed-dead `Weak<Task>` entries from both maps. Called by the
/// bulk O(N) walkers (`snapshot.rs`), which already pay O(N) to enumerate —
/// point lookups (`tid.rs::lookup`, `vpid.rs::lookup_by_vpid`) self-prune only
/// the exact entry they touch, so this sweep is what bounds `vpid_hint`
/// garbage from vpids that are never looked up again.
/// # C: O(N_tasks)
pub(super) fn prune_dead_locked(g: &mut Registry) {
    g.by_tid.retain(|_, w| w.strong_count() > 0);
    g.vpid_hint.retain(|_, w| w.strong_count() > 0);
}

#[cfg(any(test, feature = "hosted"))]
pub(super) fn clear_locked(g: &mut Registry) {
    g.by_tid.clear();
    g.vpid_hint.clear();
}
