// Free neighbours merge so the space a workload releases is reusable as one
// block, and a region that empties completely goes back to the address space.

use super::backend::TestBackend;
use crate::flags::HEAP_GROWABLE;
use crate::Heap;

#[test]
fn adjacent_free_blocks_merge_into_one() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let first = heap.allocate(&mut backend, 0, 96).unwrap();
    let second = heap.allocate(&mut backend, 0, 96).unwrap();
    let third = heap.allocate(&mut backend, 0, 96).unwrap();
    let tail = heap.free_block_count();
    assert!(heap.free(&mut backend, first));
    assert!(heap.free(&mut backend, second));
    assert_eq!(heap.free_block_count(), tail + 1, "two frees make one free block");
    let wide = heap.allocate(&mut backend, 0, 200).unwrap();
    assert_eq!(wide, first, "the merged block serves a request neither half could");
    assert!(heap.validate(&backend, third));
}

#[test]
fn a_freed_region_is_released_once_it_is_empty() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let mut live = alloc::vec::Vec::new();
    while backend.reserves < 2 { live.push(heap.allocate(&mut backend, 0, 4096).unwrap()); }
    let regions = backend.regions.len();
    for ptr in live { assert!(heap.free(&mut backend, ptr)); }
    assert!(backend.regions.len() < regions, "the grown region went back");
    assert_eq!(backend.releases, 1, "the first region stays reserved");
}

#[test]
fn growth_reserves_a_second_region_only_when_the_first_is_full() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let mut used = 512usize;
    heap.allocate(&mut backend, 0, 512).unwrap();
    assert_eq!(backend.reserves, 1);
    while backend.reserves == 1 { heap.allocate(&mut backend, 0, 512).unwrap(); used += 512; }
    assert!(used > 0x8000, "the first region served {used} bytes before growing");
}

#[test]
fn a_non_growable_heap_refuses_a_second_region() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(0);
    let mut last = Some(0);
    while last.is_some() && backend.reserves < 2 { last = heap.allocate(&mut backend, 0, 512); }
    assert_eq!(last, None);
    assert_eq!(backend.reserves, 1);
}
