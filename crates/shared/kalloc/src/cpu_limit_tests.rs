use crate::state::KAlloc;
use std::boxed::Box;

#[test]
fn allocation_contexts_use_canonical_cpu_bound() {
    let alloc = Box::new(KAlloc::new());
    assert_eq!(alloc.contexts.len(), sync::MAX_CPUS);
    assert_eq!(sync::MAX_CPUS, hal::MAX_CPUS);
}
