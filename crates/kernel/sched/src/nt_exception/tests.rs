// Hosted tests for the scheduler-owned NT exception state and the
// delivery decisions the gated frame builder consults.
// Declared path-only by the parent per `08§7`.

use super::*;
fn sample(first_chance: bool) -> Pending {
    let mut record = [0; EXCEPTION_RECORD_BYTES];
    record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].copy_from_slice(&0xc000_0005u32.to_le_bytes());
    let mut context = [0; CONTEXT_BYTES];
    context[CONTEXT_FLAGS_OFFSET..CONTEXT_FLAGS_OFFSET + 4].copy_from_slice(&CONTEXT_AMD64.to_le_bytes());
    context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8].copy_from_slice(&0x401000u64.to_le_bytes());
    context[CONTEXT_RSP_OFFSET..CONTEXT_RSP_OFFSET + 8].copy_from_slice(&0x7fff_0000u64.to_le_bytes());
    context[0x44..0x48].copy_from_slice(&2u32.to_le_bytes());
    Pending { record, context: Some(context), first_chance }
}

#[test]
fn state_retains_one_owned_exception_until_dispatch_consumes_it() {
    let state = State::new();
    let pending = sample(true);
    assert!(state.publish(pending).is_ok());
    assert!(state.is_pending());
    assert_eq!(state.publish(sample(false)), Err(sample(false)));
    assert_eq!(state.take(), Some(pending));
    assert!(!state.is_pending());
}

#[test]
fn a_hardware_trap_publishes_without_a_context_and_keeps_the_slot() {
    let state = State::new();
    let mut record = [0u8; EXCEPTION_RECORD_BYTES];
    record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4]
        .copy_from_slice(&fault::STATUS_ACCESS_VIOLATION.to_le_bytes());
    let pending = Pending::from_hardware(record);
    assert!(pending.context.is_none());
    assert!(pending.first_chance);
    assert!(pending.is_valid());
    assert!(state.publish(pending).is_ok());
    // The delivery pass, not the fault, is what may capture the context.
    assert_eq!(state.begin_delivery().map(|p| p.context), Some(None));
}

#[test]
fn a_record_with_no_exception_code_is_never_published() {
    let state = State::new();
    let pending = Pending::from_hardware([0u8; EXCEPTION_RECORD_BYTES]);
    assert!(!pending.is_valid());
    assert!(state.publish(pending).is_err());
    assert!(!state.is_pending());
}

#[test]
fn malformed_context_is_rejected_before_publication() {
    let state = State::new();
    let mut pending = sample(true);
    pending.context.as_mut().unwrap()[CONTEXT_FLAGS_OFFSET..CONTEXT_FLAGS_OFFSET + 4].fill(0);
    assert_eq!(state.publish(pending), Err(pending));
    assert!(!state.is_pending());
}

#[test]
fn exception_record_bounds_parameters_and_nested_user_links() {
    let mut record = [0u8; EXCEPTION_RECORD_BYTES];
    record[EXCEPTION_NUMBER_PARAMETERS_OFFSET..EXCEPTION_NUMBER_PARAMETERS_OFFSET + 4].copy_from_slice(&3u32.to_le_bytes());
    record[EXCEPTION_RECORD_OFFSET..EXCEPTION_RECORD_OFFSET + 8].copy_from_slice(&0x7000u64.to_le_bytes());
    record[EXCEPTION_ADDRESS_OFFSET..EXCEPTION_ADDRESS_OFFSET + 8].copy_from_slice(&0x401000u64.to_le_bytes());
    assert!(exception_record_link_valid(&record, |address| address >= 0x4000));
    record[EXCEPTION_NUMBER_PARAMETERS_OFFSET..EXCEPTION_NUMBER_PARAMETERS_OFFSET + 4].copy_from_slice(&16u32.to_le_bytes());
    assert!(!exception_record_link_valid(&record, |address| address >= 0x4000));
}

#[test]
fn exception_record_rejects_unknown_flags_and_kernel_links() {
    let mut record = [0u8; EXCEPTION_RECORD_BYTES];
    record[EXCEPTION_FLAGS_OFFSET..EXCEPTION_FLAGS_OFFSET + 4].copy_from_slice(&0x80u32.to_le_bytes());
    assert!(!exception_record_link_valid(&record, |_| true));
    record[EXCEPTION_FLAGS_OFFSET..EXCEPTION_FLAGS_OFFSET + 4].fill(0);
    record[EXCEPTION_RECORD_OFFSET..EXCEPTION_RECORD_OFFSET + 8].copy_from_slice(&0xffff_8000_0000_0000u64.to_le_bytes());
    assert!(!exception_record_link_valid(&record, |address| address < 0x0000_8000_0000_0000));
}

#[test]
fn delivery_reservation_has_single_consumer_and_can_be_cleared() {
    let state = State::new();
    let pending = sample(true);
    assert!(state.publish(pending).is_ok());
    assert_eq!(state.begin_delivery(), Some(pending));
    assert_eq!(state.begin_delivery(), None);
    assert!(state.clear());
    assert_eq!(state.take(), None);
    assert!(!state.is_pending());
}

#[test]
fn a_first_chance_raise_dispatches_and_a_second_chance_ends_the_process() {
    let mut record = [0u8; EXCEPTION_RECORD_BYTES];
    record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4]
        .copy_from_slice(&fault::STATUS_ACCESS_VIOLATION.to_le_bytes());
    assert_eq!(raise_disposition(&record, true), Disposition::Dispatch);
    // Re-dispatching a second-chance raise would re-enter the dispatcher
    // that has already refused it, forever.
    assert_eq!(raise_disposition(&record, false),
               Disposition::Terminate(fault::STATUS_ACCESS_VIOLATION as i32));
}

#[test]
fn breakpoint_dispatch_resumes_at_the_instruction_before_trap() {
    let mut record = [0u8; EXCEPTION_RECORD_BYTES];
    record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].copy_from_slice(&EXCEPTION_BREAKPOINT.to_le_bytes());
    let mut context = [0u8; CONTEXT_BYTES];
    context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8].copy_from_slice(&0x401001u64.to_le_bytes());
    assert!(prepare_dispatch_context(&record, &mut context));
    assert_eq!(u64::from_le_bytes(context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8].try_into().unwrap()), 0x401000);
}

#[test]
fn breakpoint_at_zero_is_rejected_without_mutating_context() {
    let mut record = [0u8; EXCEPTION_RECORD_BYTES];
    record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].copy_from_slice(&EXCEPTION_BREAKPOINT.to_le_bytes());
    let mut context = [0u8; CONTEXT_BYTES];
    assert!(!prepare_dispatch_context(&record, &mut context));
    assert_eq!(&context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8], &[0; 8]);
}

#[test]
fn a_resolved_frame_and_dispatcher_enter_the_dispatcher() {
    let record = access_violation_record();
    assert_eq!(delivery_outcome(&record, true, Some(0x7fff_0000_1000)), Disposition::Dispatch);
}

#[test]
fn an_execute_fault_at_an_unmapped_pc_is_still_delivered() {
    // The bad PC IS the exception: an instruction fetch from an unmapped
    // address reports itself as the access violation, with the execute
    // access parameter and the address in `ExceptionAddress`. Refusing to
    // deliver it because that address has no executable mapping would drop
    // the one exception the thread has to see.
    const BAD_PC: u64 = 0xc000_000d;
    const PF_ERR_USER_EXEC: u64 = 0x14;
    let raised = fault::x86_64::page_fault(PF_ERR_USER_EXEC, BAD_PC, BAD_PC);
    assert_eq!(raised.code, fault::STATUS_ACCESS_VIOLATION);
    assert_eq!(raised.parameters[0], fault::EXECUTE_FAULT);
    assert_eq!(raised.parameters[1], BAD_PC);
    assert_eq!(raised.address, BAD_PC);
    let record = raised.record();
    assert!(Pending::from_hardware(record).is_valid());
    assert_eq!(delivery_outcome(&record, true, Some(0x7fff_0000_1000)), Disposition::Dispatch);
}

#[test]
fn a_delivery_that_cannot_proceed_is_terminal_not_retried() {
    // Every refusal reason answers the same way. A `Dispatch` here is the
    // livelock: the return-to-user loop would re-run the arm, refuse on
    // the same input, and reach its pass bound on every kernel entry.
    let record = access_violation_record();
    let terminal = Disposition::Terminate(fault::STATUS_ACCESS_VIOLATION as i32);
    assert_eq!(delivery_outcome(&record, false, Some(0x7fff_0000_1000)), terminal);
    assert_eq!(delivery_outcome(&record, true, None), terminal);
    assert_eq!(delivery_outcome(&record, false, None), terminal);
}

#[test]
fn a_failed_delivery_retires_the_record_and_never_rearms_it() {
    let state = State::new();
    assert!(state.publish(sample(true)).is_ok());
    assert!(state.begin_delivery().is_some());
    assert!(state.fail_delivery());
    // Re-arming here is what made the work loop unable to converge.
    assert!(!state.is_pending());
    assert_eq!(state.take(), None);
    assert!(!state.fail_delivery());
}

#[test]
fn a_pending_record_is_not_retired_by_a_delivery_that_never_reserved_it() {
    let state = State::new();
    assert!(state.publish(sample(true)).is_ok());
    assert!(!state.fail_delivery());
    assert!(state.is_pending());
}

fn access_violation_record() -> [u8; EXCEPTION_RECORD_BYTES] {
    let mut record = [0u8; EXCEPTION_RECORD_BYTES];
    record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4]
        .copy_from_slice(&fault::STATUS_ACCESS_VIOLATION.to_le_bytes());
    record
}
