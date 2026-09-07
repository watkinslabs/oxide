// Resize keeps the block when it can and copies only when it must.

use super::backend::TestBackend;
use crate::backend::HeapBackend;
use crate::flags::*;
use crate::Heap;

#[test]
fn shrinking_keeps_the_block_and_returns_the_remainder() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let ptr = heap.allocate(&mut backend, 0, 512).unwrap();
    let free_blocks = heap.free_block_count();
    let same = heap.reallocate(&mut backend, 0, ptr, 64).unwrap();
    assert_eq!(same, ptr);
    assert_eq!(heap.size(&backend, ptr), Some(64));
    assert_eq!(heap.free_block_count(), free_blocks, "the split remainder merged with the tail");
}

#[test]
fn growing_into_a_free_neighbour_keeps_the_block() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let ptr = heap.allocate(&mut backend, 0, 64).unwrap();
    let neighbour = heap.allocate(&mut backend, 0, 256).unwrap();
    let guard = heap.allocate(&mut backend, 0, 64).unwrap();
    assert!(backend.write(ptr, &[0x11; 64]));
    assert!(heap.free(&mut backend, neighbour));
    let same = heap.reallocate(&mut backend, 0, ptr, 256).unwrap();
    assert_eq!(same, ptr);
    assert_eq!(heap.size(&backend, ptr), Some(256));
    let mut body = [0u8; 64];
    assert!(backend.read(ptr, &mut body));
    assert_eq!(body, [0x11; 64]);
    assert!(heap.validate(&backend, guard));
}

#[test]
fn a_blocked_growth_moves_the_body() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let ptr = heap.allocate(&mut backend, 0, 64).unwrap();
    let blocker = heap.allocate(&mut backend, 0, 64).unwrap();
    assert!(backend.write(ptr, &[0x7e; 64]));
    let moved = heap.reallocate(&mut backend, 0, ptr, 4096).unwrap();
    assert_ne!(moved, ptr);
    assert_eq!(heap.size(&backend, moved), Some(4096));
    let mut body = [0u8; 64];
    assert!(backend.read(moved, &mut body));
    assert_eq!(body, [0x7e; 64], "the old body followed the block");
    assert!(!heap.validate(&backend, ptr), "the old block was released");
    assert!(heap.validate(&backend, blocker));
}

#[test]
fn in_place_only_refuses_a_move() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let ptr = heap.allocate(&mut backend, 0, 64).unwrap();
    heap.allocate(&mut backend, 0, 64).unwrap();
    assert_eq!(heap.reallocate(&mut backend, HEAP_REALLOC_IN_PLACE_ONLY, ptr, 4096), None);
    assert_eq!(heap.size(&backend, ptr), Some(64), "the refusal left the block alone");
}

#[test]
fn zero_memory_on_growth_clears_only_the_new_bytes() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let ptr = heap.allocate(&mut backend, 0, 4096).unwrap();
    assert!(backend.fill(ptr, 4096, 0x5a));
    let same = heap.reallocate(&mut backend, HEAP_ZERO_MEMORY, ptr, 2048).unwrap();
    let grown = heap.reallocate(&mut backend, HEAP_ZERO_MEMORY, same, 3072).unwrap();
    let mut body = alloc::vec![0u8; 3072];
    assert!(backend.read(grown, &mut body));
    assert!(body[..2048].iter().all(|byte| *byte == 0x5a), "kept bytes survive");
    assert!(body[2048..].iter().all(|byte| *byte == 0), "grown bytes are zero");
}

#[test]
fn resizing_a_large_block_reports_the_new_size() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let big = heap.allocate(&mut backend, 0, crate::limits::MIN_LARGE_BLOCK_BYTES).unwrap();
    let smaller = heap.reallocate(&mut backend, 0, big, crate::limits::MIN_LARGE_BLOCK_BYTES - 4096).unwrap();
    assert_eq!(smaller, big, "a large block shrinks inside its own mapping");
    assert_eq!(heap.size(&backend, big), Some(crate::limits::MIN_LARGE_BLOCK_BYTES - 4096));
}
