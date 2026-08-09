// `ioperm(2)` / `iopl(2)` work functions: the task-state half of the port
// permission grant. The syscall shims parse and fetch `CAP_SYS_RAWIO`; every
// state transition is here, and the hardware window follows from `arch`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::task::Task;
use super::arch;
use super::bitmap::IoBitmap;
use super::ladder::{self, IoplAction};

/// The reference's `TIF_IO_BITMAP`: true exactly when this task holds SOME
/// port grant, i.e. `iopl_emul == 3` or it owns a permission map.
///
/// Not a second source of truth — the flag is recomputed from those two
/// fields at every point either changes, and it exists so the context-switch
/// path can decide in one relaxed load whether it must touch the TSS at all.
/// # C: O(1)
pub fn recompute_flag(task: &Task, has_map: bool) {
    let on = task.iopl_emul.load(Ordering::Relaxed) == 3 || has_map;
    task.tif_io_bitmap.store(on, Ordering::Relaxed);
}

/// `ksys_ioperm`. `turn_on` grants `num` ports from `from`; otherwise it
/// withdraws them.
///
/// A withdraw-only call on a task that never held a map allocates nothing and
/// returns success — there is no point building an 8 KiB deny-all map only to
/// deny more. A call that leaves NOTHING permitted drops the map entirely, so
/// a task that gives its ports back stops paying for them on every switch.
/// # C: O(IO_BITMAP_LONGS + num)
/// # Ctx: process
pub fn ioperm(task: &Task, from: u64, num: u64, turn_on: bool, capable: bool) -> i64 {
    if let Err(e) = ladder::ioperm_check(from, num, turn_on, capable) { return -(e.as_i32() as i64); }

    // Built outside the lock: 8 KiB of zeroing has no business inside a
    // spinlock, and the branch that needs it is the cold first-call one.
    let fresh = if turn_on { Some(IoBitmap::denied_all()) } else { None };

    // Preemption off across the state edit AND the window program: a switch
    // landing in between would publish a window for the half-edited map, and
    // the switch path reads the very lock held here.
    crate::preempt::preempt_disable();
    let mut g = task.io_bitmap.lock();
    let mut map = match g.take() {
        Some(m) => m,
        None => match fresh {
            Some(f) => Arc::new(f),
            // Nothing held, nothing to withdraw.
            None => { drop(g); crate::preempt::preempt_enable_no_check(); return 0; }
        },
    };
    // Copy-on-write: a map shared with a forked child must not be edited in
    // place, or the child silently gains the parent's new ports.
    let m = Arc::make_mut(&mut map);
    m.set_range(from, num, turn_on);
    match m.recompute_max() {
        Some(max) => { m.max = max; m.restamp(); *g = Some(map); }
        None => { *g = None; }
    }
    let has_map = g.is_some();
    drop(g);
    recompute_flag(task, has_map);
    arch::update(task);
    crate::preempt::preempt_enable_no_check();
    0
}

/// `SYSCALL_DEFINE1(iopl)`. Level 3 permits every port; 0-2 permit none.
///
/// The grant is emulated through the TSS permit-everything window rather than
/// the EFLAGS IOPL field, so it never hands user mode `cli`/`sti` — the same
/// choice, for the same reason, as the reference.
/// # C: O(1)
/// # Ctx: process
pub fn iopl(task: &Task, level: u32, capable: bool) -> i64 {
    match ladder::iopl_check(level, task.iopl_emul.load(Ordering::Relaxed), capable) {
        Err(e) => -(e.as_i32() as i64),
        Ok(IoplAction::Unchanged) => 0,
        Ok(IoplAction::Set(l)) => {
            crate::preempt::preempt_disable();
            task.iopl_emul.store(l, Ordering::Relaxed);
            let has_map = task.io_bitmap.lock().is_some();
            recompute_flag(task, has_map);
            arch::update(task);
            crate::preempt::preempt_enable_no_check();
            0
        }
    }
}

/// `io_bitmap_share` + the reference's inherited `iopl_emul`: a child starts
/// with the parent's level and a REFERENCE to the parent's map, not a copy.
/// The first `ioperm` on either side copies (`Arc::make_mut`), so the common
/// case — fork, never touch ports again — costs one refcount bump.
/// # C: O(1)
/// # Ctx: process (fork)
pub fn inherit(parent: &Task, child: &Task) {
    child.iopl_emul.store(parent.iopl_emul.load(Ordering::Acquire), Ordering::Release);
    let map = parent.io_bitmap.lock().clone();
    let has_map = map.is_some();
    *child.io_bitmap.lock() = map;
    recompute_flag(child, has_map);
}
