use core::cell::Cell;

use super::*;
use vmm::FaultAccess;

#[test]
fn a_missing_vma_never_enters_the_expensive_resolver() {
    let grew = Cell::new(false);
    let admitted = fault_vma(
        FaultKind::NotPresent { access: FaultAccess::Read },
        || false,
        || grew.set(true),
    );
    assert_eq!(admitted.err(), Some(Error::Inval));
    assert!(grew.get(), "a not-present fault still gets its stack-growth attempt");
}

#[test]
fn stack_growth_can_admit_a_not_present_fault() {
    let present = Cell::new(false);
    assert!(fault_vma(
        FaultKind::NotPresent { access: FaultAccess::Write },
        || present.get(),
        || present.set(true),
    ).is_ok());
}

#[test]
fn a_protection_fault_never_grows_the_stack() {
    let grew = Cell::new(false);
    let admitted = fault_vma(
        FaultKind::Protection { access: FaultAccess::Write },
        || false,
        || grew.set(true),
    );
    assert_eq!(admitted.err(), Some(Error::Inval));
    assert!(!grew.get());
}
