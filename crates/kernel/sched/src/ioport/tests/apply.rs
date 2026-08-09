use core::sync::atomic::Ordering;

use crate::ioport::{self, IoplAction};
use crate::{SchedClass, Task};
use syscall::errno::Errno;

fn task(tid: u32) -> Task { Task::new(tid, "ioport-test", SchedClass::Normal { weight: 1024 }) }
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Withdrawing ports from a task that never held a map allocates nothing and
/// succeeds — the reference returns early rather than building a deny-all map
/// just to deny more.
#[test]
fn withdraw_without_a_map_allocates_nothing() {
    let t = task(1);
    assert_eq!(ioport::ioperm(&t, 0x3f8, 8, false, false), 0);
    assert!(t.io_bitmap.lock().is_none());
    assert!(!t.tif_io_bitmap.load(Ordering::Relaxed));
}

/// The first successful grant creates the map, marks the task as holding a
/// grant, and sizes the publication window.
#[test]
fn the_first_grant_creates_the_map_and_arms_the_switch_flag() {
    let t = task(2);
    assert_eq!(ioport::ioperm(&t, 0x3f8, 8, true, true), 0);
    let g = t.io_bitmap.lock();
    let m = g.as_ref().expect("map created");
    assert!(m.permits(0x3f8) && m.permits(0x3ff) && !m.permits(0x400));
    assert_eq!(m.max, 128, "window must reach the word holding port 0x3ff");
    drop(g);
    assert!(t.tif_io_bitmap.load(Ordering::Relaxed));
}

/// Giving every port back drops the map and disarms the switch flag, so the
/// task stops costing a TSS update on every switch.
#[test]
fn giving_the_last_port_back_drops_the_map() {
    let t = task(3);
    assert_eq!(ioport::ioperm(&t, 0x60, 2, true, true), 0);
    assert!(t.tif_io_bitmap.load(Ordering::Relaxed));
    assert_eq!(ioport::ioperm(&t, 0x60, 2, false, false), 0);
    assert!(t.io_bitmap.lock().is_none());
    assert!(!t.tif_io_bitmap.load(Ordering::Relaxed));
}

/// A refused call must change NOTHING. An EPERM that had already allocated or
/// half-edited the map is the shape that leaks a grant.
#[test]
fn a_refused_call_leaves_the_task_untouched() {
    let t = task(4);
    assert_eq!(ioport::ioperm(&t, 0x3f8, 8, true, false), err(Errno::Eperm));
    assert!(t.io_bitmap.lock().is_none());
    assert_eq!(ioport::ioperm(&t, 0, 0, true, true), err(Errno::Einval));
    assert!(t.io_bitmap.lock().is_none());
    assert!(!t.tif_io_bitmap.load(Ordering::Relaxed));
}

/// A forked child SHARES the parent's map, and the first edit on either side
/// copies. Without the copy the child silently gains ports the parent granted
/// itself after the fork — the exact bug the reference's refcount prevents.
#[test]
fn fork_shares_the_map_and_the_next_edit_copies() {
    let p = task(5);
    assert_eq!(ioport::ioperm(&p, 0x60, 1, true, true), 0);
    let c = task(6);
    ioport::inherit(&p, &c);
    assert!(c.io_bitmap.lock().as_ref().expect("shared").permits(0x60));
    assert!(c.tif_io_bitmap.load(Ordering::Relaxed));

    // Parent grants itself another port AFTER the fork.
    assert_eq!(ioport::ioperm(&p, 0x64, 1, true, true), 0);
    assert!(p.io_bitmap.lock().as_ref().expect("map").permits(0x64));
    assert!(!c.io_bitmap.lock().as_ref().expect("map").permits(0x64),
            "the child must NOT inherit a grant made after the fork");
}

/// `iopl` is per-thread state inherited across fork, and level 3 alone arms
/// the switch flag — 0-2 grant nothing.
#[test]
fn iopl_level_three_arms_the_grant_and_is_inherited() {
    let t = task(7);
    assert_eq!(ioport::iopl(&t, 2, true), 0);
    assert_eq!(t.iopl_emul.load(Ordering::Relaxed), 2);
    assert!(!t.tif_io_bitmap.load(Ordering::Relaxed), "levels 0-2 grant no port");

    assert_eq!(ioport::iopl(&t, 3, true), 0);
    assert!(t.tif_io_bitmap.load(Ordering::Relaxed));

    let c = task(8);
    ioport::inherit(&t, &c);
    assert_eq!(c.iopl_emul.load(Ordering::Relaxed), 3);
    assert!(c.tif_io_bitmap.load(Ordering::Relaxed));

    // Dropping back to 0 disarms it again.
    assert_eq!(ioport::iopl(&t, 0, false), 0);
    assert!(!t.tif_io_bitmap.load(Ordering::Relaxed));
}

/// A refused `iopl` leaves the level where it was, and the no-change case is
/// decided before the capability test.
#[test]
fn iopl_refusals_do_not_move_the_level() {
    let t = task(9);
    assert_eq!(ioport::iopl(&t, 4, true), err(Errno::Einval));
    assert_eq!(t.iopl_emul.load(Ordering::Relaxed), 0);
    assert_eq!(ioport::iopl(&t, 3, false), err(Errno::Eperm));
    assert_eq!(t.iopl_emul.load(Ordering::Relaxed), 0);
    assert_eq!(ioport::iopl(&t, 0, false), 0, "no change needs no privilege");
    assert_eq!(crate::ioport::iopl_check(0, 0, false), Ok(IoplAction::Unchanged));
}
