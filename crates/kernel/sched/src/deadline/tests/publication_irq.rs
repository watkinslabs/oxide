use super::*;
use core::cell::Cell;

std::thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(true) };
}
pub(crate) struct TestIrq;
impl IrqGate for TestIrq {
    unsafe fn save_disable() -> u64 { ENABLED.with(|value| value.replace(false) as u64) }
    unsafe fn save_enable() -> u64 { ENABLED.with(|value| value.replace(true) as u64) }
    unsafe fn restore(flags: u64) { ENABLED.with(|value| value.set(flags != 0)); }
}

#[test]
fn entity_publication_masks_readers_until_generation_is_even() {
    let entity = crate::deadline::DlEntity::new();
    let initial = crate::preempt::preempt_count();
    entity.with_interrupted_publication(|| {
        assert!(!ENABLED.with(Cell::get), "IRQ reader can interrupt an odd writer");
        assert!(crate::preempt::preempt_count() > initial);
    });
    assert!(ENABLED.with(Cell::get));
    assert_eq!(crate::preempt::preempt_count(), initial);
    let _ = entity.snapshot();
}

#[test]
fn nested_irq_disabled_publication_preserves_outer_state() {
    ENABLED.with(|value| value.set(false));
    let seq = AtomicU64::new(0);
    { let _writer = Publication::begin(&seq); assert_eq!(seq.load(Ordering::Acquire), 1); }
    assert_eq!(seq.load(Ordering::Acquire), 2);
    assert!(!ENABLED.with(Cell::get));
    ENABLED.with(|value| value.set(true));
}
