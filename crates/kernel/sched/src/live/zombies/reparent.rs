use core::sync::atomic::Ordering;

use crate::TaskState;

/// B14: repair queued zombies whose parent is gone.
/// # C: O(N_zombies x N_tasks)
pub fn reap_orphans() {
    use crate::registry;
    let init = registry::lookup_by_vpid(1);
    let init_tid = init.as_ref().map(|t| t.tid).unwrap_or(1);
    let init_weak = init.as_ref().map(alloc::sync::Arc::downgrade);
    let mut reparented = false;
    let q = super::ZOMBIES.lock();
    for t in q.iter() {
        let pt = t.parent_tid.load(Ordering::Acquire);
        if pt == 0 { continue; }
        if registry::lookup(pt).is_none() {
            t.parent_tid.store(init_tid, Ordering::Release);
            if let Some(ref w) = init_weak {
                t.set_parent_weak(Some(w.clone()));
            }
            if let Some(ref p) = init { super::push_child_event(t, p); }
            reparented = true;
        }
    }
    drop(q);
    if reparented {
        if let Some(ref p) = init {
            p.sigpending.fetch_or(super::super::sigpend::Signum::Sigchld.bit(), Ordering::Release);
            super::wake_wait4_parent(init_tid);
            super::wake_task_for_signal(p);
        }
    }
}

/// Linux `forget_original_parent`: reparent live children of an exiting task
/// to PID 1 by init's internal tid, not literal visible PID 1.
/// # C: O(N_tasks)
pub fn reparent_children(dying_tid: u32) {
    use crate::registry;
    let init = registry::lookup_by_vpid(1);
    let init_tid = init.as_ref().map(|t| t.tid).unwrap_or(1);
    let init_weak = init.as_ref().map(alloc::sync::Arc::downgrade);
    let mut reparented_zombie = false;
    for tid in registry::live_tids() {
        if let Some(t) = registry::lookup(tid) {
            if t.parent_tid.load(Ordering::Acquire) == dying_tid {
                let pds = t.pdeathsig.load(Ordering::Acquire);
                if (1..=64).contains(&pds) {
                    t.sigpending.fetch_or(1u64 << (pds - 1), Ordering::Release);
                    crate::live::signal_wake_up(&t);
                }
                t.parent_tid.store(init_tid, Ordering::Release);
                if let Some(ref w) = init_weak {
                    // `t` may be a live child actively running on another
                    // CPU right now; set_parent_weak takes parent_arc's own
                    // lock so this write can't race a concurrent reader (or
                    // this task's own CLONE_PARENT self-read of the field).
                    t.set_parent_weak(Some(w.clone()));
                }
                if matches!(t.state(), TaskState::Zombie) {
                    if let Some(ref p) = init { super::push_child_event(&t, p); }
                    reparented_zombie = true;
                }
            }
        }
    }
    if reparented_zombie {
        if let Some(ref p) = init {
            p.sigpending.fetch_or(super::super::sigpend::Signum::Sigchld.bit(), Ordering::Release);
            super::wake_wait4_parent(init_tid);
            super::wake_task_for_signal(p);
        }
    }
}
