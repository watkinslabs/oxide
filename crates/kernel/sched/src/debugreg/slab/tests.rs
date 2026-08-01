// The lazy slot's contract: an unarmed task allocates nothing, an armed one
// allocates exactly once, and the allocation is released at teardown.

use super::*;
use core::sync::atomic::AtomicU64;

#[derive(Default)]
struct Shadow { v: AtomicU64 }

#[test]
fn an_unarmed_task_allocates_nothing() {
    // The whole point: `Task` carries one pointer, and a task that never arms
    // a breakpoint never pays for the register file behind it.
    let slot: Lazy<Shadow> = Lazy::new();
    assert!(slot.get().is_none());
    assert_eq!(core::mem::size_of::<Lazy<Shadow>>(), core::mem::size_of::<usize>());
}

#[test]
fn the_first_arm_allocates_and_later_ones_reuse_it() {
    let slot: Lazy<Shadow> = Lazy::new();
    let a = slot.get_or_init().expect("allocated") as *const Shadow;
    let b = slot.get_or_init().expect("live") as *const Shadow;
    assert_eq!(a, b, "a second arm must not replace the first allocation");
    assert!(slot.get().is_some());
}

#[test]
fn a_stored_value_is_read_back_through_the_slot() {
    let slot: Lazy<Shadow> = Lazy::new();
    slot.get_or_init().unwrap().v.store(0x4000, Ordering::Release);
    assert_eq!(slot.get().unwrap().v.load(Ordering::Acquire), 0x4000);
}

#[test]
fn free_releases_the_allocation_and_leaves_the_slot_empty() {
    let slot: Lazy<Shadow> = Lazy::new();
    slot.get_or_init().unwrap().v.store(7, Ordering::Release);
    slot.free();
    assert!(slot.get().is_none(), "teardown must leave nothing behind");
    // Freeing twice is harmless — the swap claims the pointer exactly once.
    slot.free();
    // And the slot is reusable, which is what makes the double-free safe.
    assert_eq!(slot.get_or_init().unwrap().v.load(Ordering::Acquire), 0);
    slot.free();
}
