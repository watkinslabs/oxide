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

// ── the read-before-write ordering ──────────────────────────────────────
// The rights register is USER-writable, so the per-task field is a snapshot
// and NOT the truth while a thread runs. These drive a stand-in register so
// the ordering is pinned on a host that has none.

fn arm_fake(initial: u64) {
    super::fake::VALUE.store(initial, Ordering::Relaxed);
    super::fake::ARMED.store(true, Ordering::Relaxed);
}
fn disarm_fake() { super::fake::ARMED.store(false, Ordering::Relaxed); }

// THE invariant: a thread that changed its own rights with an unprivileged
// register write, without the kernel ever seeing it, must still hold those
// rights the next time it is scheduled. `switch_to` has to READ the live
// register into the outgoing task before it loads the incoming one's — a
// write-only handoff throws the change away, and this test fails if the read
// is removed or reordered after the write.
#[test]
fn a_user_write_the_kernel_never_saw_survives_a_switch() {
    let _g = ();
    let a = task(10);
    let b = task(11);
    a.pkey_rights.store(0x1111, Ordering::Relaxed);
    b.pkey_rights.store(0x2222, Ordering::Relaxed);
    arm_fake(0x1111);

    // Userspace opens a key behind the kernel's back.
    super::fake::VALUE.store(0xBEEF, Ordering::Relaxed);
    // ... and is switched away from.
    switch_to(&a, &b);
    assert_eq!(a.pkey_rights.load(Ordering::Relaxed), 0xBEEF,
        "the outgoing task's snapshot must capture the user's write");
    assert_eq!(read_live(), 0x2222, "the incoming task's rights must be installed");

    // Switching back must restore what userspace had, not the stale snapshot.
    switch_to(&b, &a);
    assert_eq!(read_live(), 0xBEEF);
    disarm_fake();
}

// The incoming task's value is what ends up in the register even when the
// outgoing task's live value differs from every stored snapshot.
#[test]
fn the_incoming_tasks_rights_are_installed_not_the_outgoing_tasks() {
    let a = task(12);
    let b = task(13);
    a.pkey_rights.store(0xAAAA, Ordering::Relaxed);
    b.pkey_rights.store(0xBBBB, Ordering::Relaxed);
    arm_fake(0xCCCC);
    switch_to(&a, &b);
    assert_eq!(a.pkey_rights.load(Ordering::Relaxed), 0xCCCC);
    assert_eq!(b.pkey_rights.load(Ordering::Relaxed), 0xBBBB);
    assert_eq!(read_live(), 0xBBBB);
    disarm_fake();
}
