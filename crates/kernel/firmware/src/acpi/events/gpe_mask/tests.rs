use super::*;
use alloc::vec;
use core::cell::RefCell;

fn port(address: u64) -> Gas {
    Gas { space_id: super::super::SPACE_SYSTEM_IO, bit_width: 16,
        bit_offset: 0, access_width: 1, address }
}

fn test_runtime() -> Runtime {
    let block = Block::from_fadt(port(0x620), 2, 0).unwrap();
    Runtime {
        blocks: vec![block],
        methods: core::iter::repeat_with(|| None).take(super::super::GPE_LIMIT).collect(),
        worker_queued: AtomicBool::new(false),
        wake_mask: WakeMask::new(&[block]),
    }
}

#[test]
fn sleep_entry_disables_runtime_clears_status_then_arms_only_wake_bits() {
    let runtime = test_runtime();
    let writes = RefCell::new(Vec::new());
    assert!(switch_to_wake(&runtime,
        |_, offset| (offset == 1).then_some(0b11),
        |_, offset, value| { writes.borrow_mut().push((offset, value)); Some(()) },
        |gpe| gpe == 2));
    assert_eq!(*writes.borrow(), vec![(1, 0), (0, u8::MAX), (1, 0b100)]);
    assert!(runtime.wake_mask.armed.load(Ordering::Acquire));
}

#[test]
fn resume_disables_the_wake_mask_before_restoring_the_exact_runtime_mask() {
    let runtime = test_runtime();
    runtime.wake_mask.saved[0].store(0b1010, Ordering::Release);
    runtime.wake_mask.armed.store(true, Ordering::Release);
    let writes = RefCell::new(Vec::new());
    assert!(restore(&runtime,
        &mut |_, offset, value| { writes.borrow_mut().push((offset, value)); Some(()) }));
    assert_eq!(*writes.borrow(), vec![(1, 0), (1, 0b1010)]);
    assert!(!runtime.wake_mask.armed.load(Ordering::Acquire));
}

#[test]
fn an_unprepared_device_does_not_enter_the_wake_mask() {
    let runtime = test_runtime();
    let writes = RefCell::new(Vec::new());
    assert!(switch_to_wake(&runtime,
        |_, offset| (offset == 1).then_some(0b11),
        |_, offset, value| { writes.borrow_mut().push((offset, value)); Some(()) },
        |_| false));
    assert_eq!(*writes.borrow(), vec![(1, 0), (0, u8::MAX), (1, 0)]);
}

#[test]
fn a_failed_transition_restores_the_runtime_mask() {
    let runtime = test_runtime();
    let writes = RefCell::new(Vec::new());
    let failed = AtomicBool::new(false);
    assert!(!switch_to_wake(&runtime,
        |_, offset| (offset == 1).then_some(0b1010),
        |_, offset, value| {
            writes.borrow_mut().push((offset, value));
            if offset == 0 && !failed.swap(true, Ordering::AcqRel) { None } else { Some(()) }
        }, |gpe| gpe == 2));
    assert!(writes.borrow().ends_with(&[(1, 0), (1, 0b1010)]));
    assert!(!runtime.wake_mask.armed.load(Ordering::Acquire));
}

#[test]
fn a_failed_runtime_mask_read_changes_no_hardware() {
    let runtime = test_runtime();
    let writes = RefCell::new(Vec::new());
    assert!(!switch_to_wake(&runtime, |_, _| None,
        |_, offset, value| { writes.borrow_mut().push((offset, value)); Some(()) }, |_| true));
    assert!(writes.borrow().is_empty(), "partial state was written before all runtime masks were saved");
}
