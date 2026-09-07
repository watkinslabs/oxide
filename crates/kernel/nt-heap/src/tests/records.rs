// Walk order and the per-allocation user records.

use super::backend::TestBackend;
use crate::flags::*;
use crate::Heap;

#[test]
fn a_walk_reports_every_block_in_address_order() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let first = heap.allocate(&mut backend, 0, 64).unwrap();
    let second = heap.allocate(&mut backend, 0, 128).unwrap();
    let third = heap.allocate(&mut backend, 0, 64).unwrap();
    assert!(heap.free(&mut backend, second));
    let mut cursor = 0;
    let mut seen = alloc::vec::Vec::new();
    while let Some(entry) = heap.walk(&backend, cursor) { cursor = entry.data; seen.push(entry); }
    assert_eq!(seen[0].data, first);
    assert!(seen[0].busy);
    assert_eq!(seen[1].data, second);
    assert!(!seen[1].busy, "the freed block is reported free");
    assert_eq!(seen[2].data, third);
    assert!(seen.windows(2).all(|pair| pair[0].data < pair[1].data));
}

#[test]
fn user_records_follow_the_allocation_and_die_with_it() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let plain = heap.allocate(&mut backend, 0, 64).unwrap();
    assert_eq!(heap.user_info(plain), None, "no record without the flag");
    assert!(!heap.set_user_value(plain, 7));
    let ptr = heap.allocate(&mut backend, HEAP_ADD_USER_INFO, 64).unwrap();
    assert_eq!(heap.user_info(ptr), Some((0, HEAP_ADD_USER_INFO & !HEAP_ADD_USER_INFO)));
    assert!(heap.set_user_value(ptr, 0x1234));
    heap.allocate(&mut backend, 0, 64).unwrap();
    let moved = heap.reallocate(&mut backend, 0, ptr, 4096).unwrap();
    assert_ne!(moved, ptr);
    assert_eq!(heap.user_info(moved).map(|info| info.0), Some(0x1234), "the record moved with the body");
    assert!(heap.free(&mut backend, moved));
    assert_eq!(heap.user_info(moved), None);
}
