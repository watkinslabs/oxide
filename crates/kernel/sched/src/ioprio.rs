// I/O priority: the packed `int` ABI, the nice-derived fallback, and the
// per-task `io_context` object that `CLONE_IO` shares.
//
// This lives in `sched` rather than in the syscall layer because BOTH sides
// need it: `ioprio_set`/`ioprio_get` write and read it, and the block layer
// stamps every request with the submitting task's effective priority and
// dispatches by it. A copy on either side would be a split source of truth
// for the same field.
//
// Ungated on purpose — every rule below is hosted-tested.

extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};

/// Bit position of the class field inside the packed value.
pub const CLASS_SHIFT: u32 = 13;
/// Class field width, as a mask applied after shifting.
pub const CLASS_MASK: u32 = 7;
/// Level ("data") field: the LOW THREE bits, not the low thirteen. Bits
/// [12:3] are the hint field and are not part of the level.
pub const LEVEL_MASK: u32 = 7;

/// `IOPRIO_CLASS_NONE` — nothing set; the effective priority is derived from
/// the task's nice value.
pub const CLASS_NONE: u32 = 0;
/// `IOPRIO_CLASS_RT`.
pub const CLASS_RT: u32 = 1;
/// `IOPRIO_CLASS_BE`.
pub const CLASS_BE: u32 = 2;
/// `IOPRIO_CLASS_IDLE`.
pub const CLASS_IDLE: u32 = 3;

/// `IOPRIO_DEFAULT` — class NONE, level 0.
pub const DEFAULT: i32 = 0;

/// Number of distinct levels within a class.
pub const NR_LEVELS: u32 = 8;
/// Nice values per I/O level: the [-20, 19] nice range folded onto 8 levels.
pub const NICE_PER_LEVEL: i32 = 5;
/// Nice bias applied before folding, so nice -20 lands on level 0.
pub const NICE_BIAS: i32 = 20;

/// Class of a packed value. # C: O(1)
pub fn prio_class(v: i32) -> u32 { ((v as u32) >> CLASS_SHIFT) & CLASS_MASK }

/// Level of a packed value. # C: O(1)
pub fn prio_level(v: i32) -> u32 { (v as u32) & LEVEL_MASK }

/// Pack a class/level pair, with no hint bits. # C: O(1)
pub fn prio_value(class: u32, level: u32) -> i32 { ((class << CLASS_SHIFT) | level) as i32 }

/// Whether a packed value names a real class — the test that decides whether
/// a fork copies the parent's priority forward at all. Class NONE and the
/// undefined classes above IDLE are not valid.
/// # C: O(1)
pub fn prio_valid(v: i32) -> bool {
    let c = prio_class(v);
    c > CLASS_NONE && c <= CLASS_IDLE
}

/// Level derived from a nice value when no explicit priority was set:
/// `(nice + 20) / 5`, so the whole nice range maps onto levels 0..=7.
/// # C: O(1)
pub fn nice_to_level(nice: i32) -> u32 { ((nice + NICE_BIAS) / NICE_PER_LEVEL) as u32 }

/// Class derived from the scheduling policy when no explicit priority was
/// set: an idle-policy task gets IDLE, an RT/DEADLINE task gets RT, and
/// everything else gets BE.
/// # C: O(1)
pub fn nice_to_class(idle_policy: bool, rt_policy: bool) -> u32 {
    if idle_policy { CLASS_IDLE } else if rt_policy { CLASS_RT } else { CLASS_BE }
}

/// Effective priority: the stored value when its class is set, otherwise the
/// class and level derived from the task's policy and nice value. This is
/// what the block layer stamps on a request and what `ioprio_get` reports for
/// the group and user target sets.
/// # C: O(1)
pub fn effective(stored: i32, nice: i32, idle_policy: bool, rt_policy: bool) -> i32 {
    if prio_class(stored) != CLASS_NONE { return stored; }
    prio_value(nice_to_class(idle_policy, rt_policy), nice_to_level(nice))
}

/// Fold two priorities to the more urgent one. The packed layout puts the
/// class in the high bits and a lower class number means higher urgency, so a
/// plain minimum orders by class first and level second.
/// # C: O(1)
pub fn best(a: i32, b: i32) -> i32 { core::cmp::min(a as u16, b as u16) as i32 }

/// Per-task I/O priority object.
///
/// A separate refcounted object rather than a plain field because `CLONE_IO`
/// SHARES it between parent and child: a later `ioprio_set` in either is then
/// visible to both. A copied field cannot express that, and a task that never
/// set a priority behaves exactly like one with no context at all — both
/// report [`DEFAULT`].
pub struct IoContext {
    ioprio: AtomicI32,
}

impl IoContext {
    /// # C: O(1)
    pub fn new(ioprio: i32) -> Arc<Self> { Arc::new(Self { ioprio: AtomicI32::new(ioprio) }) }

    /// Raw stored value, reported verbatim by `ioprio_get(IOPRIO_WHO_PROCESS)`
    /// so userspace can tell "never set" from an explicit priority.
    /// # C: O(1)
    pub fn ioprio(&self) -> i32 { self.ioprio.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn set_ioprio(&self, v: i32) { self.ioprio.store(v, Ordering::Release) }
}

/// Fork/clone handling of the I/O context.
///
/// With `CLONE_IO` the child SHARES the parent's context, so a later
/// `ioprio_set` on either task is observed by both. Without it the child gets
/// its own context, seeded with the parent's priority only when that priority
/// names a real class — an unset parent priority leaves the child unset
/// rather than freezing the parent's nice-derived value into it.
/// # C: O(1)
pub fn copy_io(parent: &Arc<IoContext>, clone_io: bool) -> Arc<IoContext> {
    if clone_io { return Arc::clone(parent); }
    let v = parent.ioprio();
    IoContext::new(if prio_valid(v) { v } else { DEFAULT })
}

#[cfg(test)]
mod tests;
