// The rights-register handoff, on a target that has no such register: every
// operation must be inert rather than corrupting per-task state.

use super::*;
use crate::{SchedClass, Task};

fn task(tid: u32) -> Task { Task::new(tid, "pkru", SchedClass::Normal { weight: 1024 }) }

// Hosted builds have no rights register, so nothing is denied and the default
// is the all-permissive zero.
#[test]
fn an_absent_register_denies_nothing() {
    assert!(!supported());
    assert_eq!(init_value(), 0);
    assert_eq!(read_live(), 0);
    write_live(0xFFFF_FFFF_FFFF_FFFF);
    assert_eq!(read_live(), 0);
}

// With no register to switch, the handoff must leave BOTH tasks' snapshots
// exactly as they were — an unconditional read-back would zero the outgoing
// task's field on every switch.
#[test]
fn the_handoff_is_inert_without_a_register() {
    let prev = task(1);
    let next = task(2);
    prev.pkey_rights.store(0xDEAD_BEEF, Ordering::Relaxed);
    next.pkey_rights.store(0x1234_5678, Ordering::Relaxed);
    switch_to(&prev, &next);
    assert_eq!(prev.pkey_rights.load(Ordering::Relaxed), 0xDEAD_BEEF);
    assert_eq!(next.pkey_rights.load(Ordering::Relaxed), 0x1234_5678);
}

// A task is born holding the default rather than an arbitrary value.
#[test]
fn a_new_task_starts_at_the_default() {
    assert_eq!(task(3).pkey_rights.load(Ordering::Relaxed), init_value());
}

// exec resets the snapshot: a fresh program must not inherit rights the old
// one opened, because its keys mean something else.
#[test]
fn exec_resets_the_snapshot_to_the_default() {
    let t = task(4);
    t.pkey_rights.store(0xAAAA_AAAA, Ordering::Relaxed);
    reset_on_exec(&t);
    assert_eq!(t.pkey_rights.load(Ordering::Relaxed), init_value());
}
