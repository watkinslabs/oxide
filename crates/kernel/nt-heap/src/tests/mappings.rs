// The measured cost this allocator exists to remove: address-space operations
// per allocation. The control restores the page-per-allocation shape and shows
// the same counter reporting one mapping per allocation.

use super::backend::TestBackend;
use crate::backend::HeapBackend;
use crate::flags::HEAP_GROWABLE;
use crate::limits::round_up;
use crate::Heap;

const ALLOCATIONS: usize = 1000;
const BODY: usize = 48;

#[test]
fn small_allocations_cost_a_constant_number_of_mappings() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let mut live = alloc::vec::Vec::new();
    for _ in 0..ALLOCATIONS { live.push(heap.allocate(&mut backend, 0, BODY).unwrap()); }
    for ptr in &live { assert!(heap.free(&mut backend, *ptr)); }
    assert!(backend.mappings() <= 4, "{} mappings for {ALLOCATIONS} allocate/free pairs", backend.mappings());
}

#[test]
fn allocate_free_in_a_loop_never_grows_the_address_space() {
    let mut backend = TestBackend::new();
    let mut heap = Heap::new(HEAP_GROWABLE);
    let first = heap.allocate(&mut backend, 0, BODY).unwrap();
    assert!(heap.free(&mut backend, first));
    let settled = backend.mappings();
    for _ in 0..ALLOCATIONS {
        let ptr = heap.allocate(&mut backend, 0, BODY).unwrap();
        assert_eq!(ptr, first, "a freed block is handed straight back");
        assert!(heap.free(&mut backend, ptr));
    }
    assert_eq!(backend.mappings(), settled);
}

// Positive control: the same counter over the page-per-allocation shape this
// branch replaced — one reservation per allocation, released on free.
#[test]
fn page_per_allocation_control_costs_one_mapping_each() {
    let mut backend = TestBackend::new();
    let mut live = alloc::vec::Vec::new();
    for _ in 0..ALLOCATIONS {
        let size = round_up(BODY, 0x1000);
        let base = backend.reserve(size).unwrap();
        assert!(backend.commit(base, size));
        live.push((base, size));
    }
    for (base, size) in live { assert!(backend.release(base, size)); }
    assert_eq!(backend.mappings(), 2 * ALLOCATIONS);
}
