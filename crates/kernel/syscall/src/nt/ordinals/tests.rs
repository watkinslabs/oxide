use super::*;

fn args() -> SyscallArgs { SyscallArgs { a0: 0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 } }

#[test]
fn the_ordinal_word_splits_into_a_table_and_a_number() {
    assert_eq!((table_of(0), number_of(0)), (0, 0));
    assert_eq!((table_of(6), number_of(6)), (0, 6));
    assert_eq!((table_of(0x0fff), number_of(0x0fff)), (0, 0xfff));
    // The window surface is the next table up, which is why a raw window
    // ordinal starts at 0x1000 and must not be read as a runtime service.
    assert_eq!((table_of(0x1000), number_of(0x1000)), (1, 0));
    assert_eq!((table_of(0x15a6), number_of(0x15a6)), (1, 0x5a6));
    assert_eq!(table_of(0x3fff), 3);
    assert_eq!(runtime_number(0x1000), None);
    assert_eq!(runtime_number(6), Some(6));
}

#[test]
fn a_slot_distinguishes_the_zero_selector_from_an_unfilled_slot() {
    let zero = NtService::AllocateVirtualMemory;
    assert_eq!(zero as u16, 0);
    assert_ne!(slot_for(zero), EMPTY);
    assert_eq!(selector_of(EMPTY), None);
    assert_eq!(selector_of(slot_for(zero)), Some(0));
    assert_eq!(selector_of(slot_for(NtService::TerminateProcess)), Some(NtService::TerminateProcess as u32));
}

#[test]
fn no_ordinal_is_claimed_until_a_module_numbering_is_installed_and_none_after_it_is_cleared() {
    clear();
    assert!(!installed());
    assert_eq!(filled(), 0);
    // Linux `read` is syscall 0 and the shipped stub for a runtime service can
    // carry ordinal 0. An empty table must claim neither.
    assert_eq!(call_for_ordinal(0, args()), None);
    assert!(!is_runtime_ordinal(0));

    let filled_now = install([(6u32, NtService::ReadFile), (0x1000u32, NtService::Close)].into_iter());
    assert_eq!(filled_now, 1, "an ordinal outside the runtime table is not this table's business");
    assert!(installed());
    assert_eq!(filled(), 1);
    assert_eq!(call_for_ordinal(6, args()).map(|call| call.service), Some(NtService::ReadFile));
    // The window table keeps its own route: this table must not answer for it.
    assert_eq!(call_for_ordinal(0x1000, args()), None);
    // A number the module never used stays unclaimed, but is still a runtime
    // ordinal and so must not fall through to a Linux syscall of that number.
    assert_eq!(call_for_ordinal(7, args()), None);
    assert!(is_runtime_ordinal(7));
    assert!(!is_runtime_ordinal(0x1000));

    clear();
    assert_eq!(call_for_ordinal(6, args()), None);
    assert!(!installed());
}
