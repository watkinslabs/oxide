// Block geometry the ABI promises: 16-byte data alignment, exact reported
// sizes, zero-on-request, and a private mapping only for large blocks.

use super::backend::TestBackend;
use crate::backend::HeapBackend;
use crate::flags::*;
use crate::limits::{BLOCK_ALIGN, MIN_LARGE_BLOCK_BYTES};
use crate::Heap;

#[test]
fn data_pointers_are_block_aligned_and_sizes_are_exact() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    for size in [1usize, 7, 15, 16, 17, 48, 100, 4096, 65537] {
        let ptr = heap.allocate(&mut backend, 0, size).unwrap();
        assert_eq!(ptr % BLOCK_ALIGN as u64, 0, "size {size}");
        assert_eq!(heap.size(&backend, ptr), Some(size), "size {size}");
        assert!(heap.validate(&backend, ptr));
    }
}

#[test]
fn allocations_do_not_overlap_and_survive_writes() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let mut live = alloc::vec::Vec::new();
    for index in 0..200usize {
        let ptr = heap.allocate(&mut backend, 0, 64).unwrap();
        assert!(backend.write(ptr, &[index as u8; 64]));
        live.push(ptr);
    }
    for (index, ptr) in live.iter().enumerate() {
        let mut body = [0u8; 64];
        assert!(backend.read(*ptr, &mut body));
        assert_eq!(body, [index as u8; 64], "block {index} was overwritten");
    }
}

#[test]
fn zero_memory_clears_a_reused_block() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let dirty = heap.allocate(&mut backend, 0, 128).unwrap();
    assert!(backend.fill(dirty, 128, 0xcd));
    assert!(heap.free(&mut backend, dirty));
    let ptr = heap.allocate(&mut backend, HEAP_ZERO_MEMORY, 128).unwrap();
    assert_eq!(ptr, dirty, "the freed block is the one reused");
    let mut body = [0xffu8; 128];
    assert!(backend.read(ptr, &mut body));
    assert_eq!(body, [0u8; 128]);
}

#[test]
fn foreign_and_double_frees_are_refused() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let ptr = heap.allocate(&mut backend, 0, 32).unwrap();
    assert!(!heap.free(&mut backend, ptr + 1), "unaligned pointer");
    assert!(!heap.free(&mut backend, 0xdead_0000), "pointer outside every region");
    assert!(heap.free(&mut backend, ptr));
    assert!(!heap.free(&mut backend, ptr), "second free of the same block");
    assert!(heap.free(&mut backend, 0), "a null free succeeds");
}

#[test]
fn a_large_block_takes_its_own_mapping_and_gives_it_back() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let small = heap.allocate(&mut backend, 0, 32).unwrap();
    let reserves = backend.reserves;
    let big = heap.allocate(&mut backend, 0, MIN_LARGE_BLOCK_BYTES).unwrap();
    assert_eq!(backend.reserves, reserves + 1);
    assert_eq!(heap.size(&backend, big), Some(MIN_LARGE_BLOCK_BYTES));
    assert!(backend.write(big, &[0xa5; 16]));
    assert!(heap.free(&mut backend, big));
    assert_eq!(backend.releases, 1);
    assert!(heap.validate(&backend, small), "the small block is untouched");
}

#[test]
fn destroy_releases_every_region() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    for _ in 0..2000 { heap.allocate(&mut backend, 0, 200).unwrap(); }
    heap.allocate(&mut backend, 0, MIN_LARGE_BLOCK_BYTES).unwrap();
    heap.destroy(&mut backend);
    assert!(backend.regions.is_empty());
}
