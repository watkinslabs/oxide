use crate::state::KAlloc;

#[test]
fn allocation_contexts_use_canonical_cpu_bound() {
    let alloc = KAlloc::new();
    assert_eq!(alloc.contexts.len(), sync::MAX_CPUS);
    assert_eq!(sync::MAX_CPUS, hal::MAX_CPUS);
}
