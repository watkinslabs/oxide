use super::*;
use core::cell::Cell;

fn port(address: u64) -> Gas {
    Gas { space_id: SPACE_SYSTEM_IO, bit_width: 32, bit_offset: 0, access_width: 1, address }
}

#[test]
fn blocks_split_status_from_enable_and_bound_the_number_space() {
    let block = Block::from_fadt(port(0x620), 4, 0x20).unwrap();
    assert_eq!(block.registers, 2);
    assert_eq!(block.slot(0x20), Some((0, 1)));
    assert_eq!(block.slot(0x2f), Some((1, 0x80)));
    assert_eq!(block.slot(0x30), None);
    assert_eq!(Block::from_fadt(port(0x620), 3, 0).unwrap().registers, 1,
        "an unmatched trailing byte does not discard a complete pair");
    assert!(Block::from_fadt(port(0x620), 1, 0).is_none());
    assert!(Block::from_fadt(port(0x620), 4, 0xf8).is_none());
}

#[test]
fn overlapping_fadt_blocks_are_detected() {
    let first = Block::from_fadt(port(0x620), 4, 0).unwrap();
    let overlap = Block::from_fadt(port(0x630), 2, 8).unwrap();
    let separate = Block::from_fadt(port(0x640), 2, 16).unwrap();
    assert!(overlaps(first, overlap));
    assert!(!overlaps(first, separate));
}

#[test]
fn fixed_event_blocks_are_split_into_equal_status_and_enable_halves() {
    assert_eq!(fixed_enable_half(4), Some((2, 2)));
    assert_eq!(fixed_enable_half(2), Some((1, 1)));
    assert_eq!(fixed_enable_half(0), None);
    assert_eq!(fixed_enable_half(3), Some((1, 1)));
    assert_eq!(fixed_enable_half(1), None);
}

#[test]
fn acpi_mode_transition_follows_fadt_capabilities() {
    let mut registers = EventRegisters::default();
    assert_eq!(mode_transition(registers, false), ModeTransition::Complete,
        "zero SMI_CMD means firmware has no legacy mode");
    registers.smi_command = 0xb2;
    assert_eq!(mode_transition(registers, true), ModeTransition::Complete);
    assert_eq!(mode_transition(registers, false), ModeTransition::Unsupported,
        "both zero transition values advertise no mode switch");
    registers.acpi_disable = 0xa1;
    assert_eq!(mode_transition(registers, false), ModeTransition::Write(0),
        "a zero enable value remains meaningful when disable is nonzero");
    registers.acpi_enable = 0xa0;
    assert_eq!(mode_transition(registers, false), ModeTransition::Write(0xa0));
}

#[test]
fn sci_enable_is_the_union_of_the_required_a_and_optional_b_registers() {
    assert!(combined_sci_enabled(Some(0), true, Some(SCI_ENABLE)));
    assert!(combined_sci_enabled(Some(SCI_ENABLE), false, None));
    assert!(!combined_sci_enabled(None, true, Some(SCI_ENABLE)),
        "a failed required register makes the mode unreadable");
    assert!(!combined_sci_enabled(Some(SCI_ENABLE), true, None),
        "a declared B register must also be readable");
}

#[test]
fn an_active_owned_gpe_is_masked_and_marked_for_deferred_execution() {
    let block = Block::from_fadt(port(0x620), 2, 0).unwrap();
    let mut methods: Vec<Option<Method>> = core::iter::repeat_with(|| None)
        .take(GPE_LIMIT).collect();
    methods[0] = Some(Method {
        path: String::from("\\_GPE._L00"), edge: false, pending: AtomicBool::new(false),
    });
    let runtime = Runtime { blocks: alloc::vec![block], methods,
        worker_queued: AtomicBool::new(false),
        wake_mask: gpe_mask::WakeMask::new(&[block]) };
    let masked = Cell::new(None);
    let (handled, deferred) = mask_active(&runtime,
        |_, offset| match offset { 0 => Some(0b11), 1 => Some(0b11), _ => None },
        |_, offset, value| { masked.set(Some((offset, value))); Some(()) });

    assert!(handled);
    assert!(deferred);
    assert_eq!(masked.get(), Some((1, 0)), "owned and unknown active sources are masked");
    assert!(runtime.method(0).unwrap().pending.load(Ordering::Acquire));
    assert!(runtime.method(1).is_none(), "an unknown source is never fabricated as work");
}

#[test]
fn an_edge_gpe_is_cleared_after_masking_and_before_deferred_execution() {
    let block = Block::from_fadt(port(0x620), 2, 0).unwrap();
    let mut methods: Vec<Option<Method>> = core::iter::repeat_with(|| None)
        .take(GPE_LIMIT).collect();
    methods[2] = Some(Method {
        path: String::from("\\_GPE._E02"), edge: true, pending: AtomicBool::new(false),
    });
    let runtime = Runtime { blocks: alloc::vec![block], methods,
        worker_queued: AtomicBool::new(false),
        wake_mask: gpe_mask::WakeMask::new(&[block]) };
    let writes = core::cell::RefCell::new(Vec::new());
    let (handled, deferred) = mask_active(&runtime,
        |_, offset| match offset { 0 => Some(0b100), 1 => Some(0b100), _ => None },
        |_, offset, value| { writes.borrow_mut().push((offset, value)); Some(()) });

    assert_eq!((handled, deferred), (true, true));
    assert_eq!(*writes.borrow(), alloc::vec![(1, 0), (0, 0b100)],
        "masking must precede the edge-status clear");
    assert!(runtime.method(2).unwrap().pending.load(Ordering::Acquire));
}

#[test]
fn a_gpe_whose_aml_method_failed_stays_masked() {
    let block = Block::from_fadt(port(0x620), 2, 0).unwrap();
    let writes = core::cell::RefCell::new(Vec::new());
    assert!(!finish_method(false, true, block, 0, 0b100,
        |_, _| Some(0),
        |_, offset, value| { writes.borrow_mut().push((offset, value)); Some(()) }));
    assert!(writes.borrow().is_empty(),
        "a failed interpreter must not re-enable an unconsumed source");

    assert!(finish_method(true, true, block, 0, 0b100,
        |_, offset| (offset == 1).then_some(0b10),
        |_, offset, value| { writes.borrow_mut().push((offset, value)); Some(()) }));
    assert_eq!(*writes.borrow(), alloc::vec![(1, 0b110)]);
}
