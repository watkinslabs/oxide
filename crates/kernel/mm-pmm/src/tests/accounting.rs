use super::*;

#[test]
fn buddy_snapshot_separates_managed_reserved_runtime_and_events() {
    let pmm = build(64);
    assert_eq!(pmm.snapshot(), PmmSnapshot {
        managed_pages: 64, free_pages: 64, allocated_pages: 0, reserved_pages: 0,
        alloc_events: 0, alloc_event_pages: 0, free_events: 0, free_event_pages: 0,
    });
    pmm.reserve_early(Pfn(0), 5).unwrap();
    let first = pmm.alloc(Order(0)).unwrap();
    let run = pmm.alloc(Order(2)).unwrap();
    let held = pmm.snapshot();
    assert_eq!(held.managed_pages, 64);
    assert_eq!(held.free_pages, 64 - 5 - 1 - 4);
    assert_eq!(held.reserved_pages, 5);
    assert_eq!(held.allocated_pages, 5);
    assert_eq!(held.alloc_events, 2);
    assert_eq!(held.alloc_event_pages, 5);
    assert_eq!(held.free_events, 0);
    // SAFETY: both blocks were allocated immediately above.
    unsafe { pmm.free(first, Order(0)); }
    // SAFETY: both blocks were allocated immediately above.
    unsafe { pmm.free(run, Order(2)); }
    let released = pmm.snapshot();
    assert_eq!(released.free_pages, 64 - 5);
    assert_eq!(released.allocated_pages, 0);
    assert_eq!(released.reserved_pages, 5);
    assert_eq!(released.free_events, 2);
    assert_eq!(released.free_event_pages, 5);
}

#[test]
fn failed_buddy_allocations_do_not_create_events() {
    let pmm = build(1);
    let _held = pmm.alloc(Order(0)).unwrap();
    assert_eq!(pmm.alloc(Order(0)), Err(Error::NoMem));
    let snapshot = pmm.snapshot();
    assert_eq!(snapshot.alloc_events, 1);
    assert_eq!(snapshot.alloc_event_pages, 1);
    assert_eq!(snapshot.free_events, 0);
}
