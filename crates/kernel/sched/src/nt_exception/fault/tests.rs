use super::*;

const PC: u64 = 0x0000_7ff8_1234_5670;
const ADDR: u64 = 0x0000_0000_dead_beef;

fn parameters(record: &[u8; EXCEPTION_RECORD_BYTES], index: usize) -> u64 {
    let at = PARAMETERS_OFFSET + index * 8;
    u64::from_le_bytes(record[at..at + 8].try_into().unwrap())
}

fn field32(record: &[u8; EXCEPTION_RECORD_BYTES], offset: usize) -> u32 {
    u32::from_le_bytes(record[offset..offset + 4].try_into().unwrap())
}

#[test]
fn a_read_fault_reports_access_violation_with_the_faulting_address() {
    let raised = x86_64::page_fault(0x4, ADDR, PC);
    assert_eq!(raised.code, STATUS_ACCESS_VIOLATION);
    assert_eq!(raised.count, 2);
    assert_eq!(raised.parameters[0], READ_FAULT);
    assert_eq!(raised.parameters[1], ADDR);
    assert_eq!(raised.address, PC);
}

#[test]
fn the_write_bit_of_the_page_fault_error_code_selects_the_write_access_parameter() {
    // Present page, user-mode write: bits PROT|WRITE|USER.
    assert_eq!(x86_64::page_fault(0x7, ADDR, PC).parameters[0], WRITE_FAULT);
    // Absent mapping, user-mode write.
    assert_eq!(x86_64::page_fault(0x6, ADDR, PC).parameters[0], WRITE_FAULT);
}

#[test]
fn an_instruction_fetch_fault_reports_the_execute_access_parameter() {
    // User-mode instruction fetch: bit 4 becomes bit 3 of the parameter.
    assert_eq!(x86_64::page_fault(0x14, ADDR, PC).parameters[0], EXECUTE_FAULT);
    // A write during an instruction fetch cannot occur, but the mask must
    // still keep exactly the two bits the parameter is defined over.
    assert_eq!(x86_64::page_fault(0xffff_ffff, ADDR, PC).parameters[0],
               WRITE_FAULT | EXECUTE_FAULT);
}

#[test]
fn the_record_encodes_code_address_count_and_only_the_named_parameters() {
    let record = x86_64::page_fault(0x6, ADDR, PC).record();
    assert_eq!(field32(&record, CODE_OFFSET), STATUS_ACCESS_VIOLATION);
    assert_eq!(field32(&record, FLAGS_OFFSET), 0);
    assert_eq!(u64::from_le_bytes(record[ADDRESS_OFFSET..ADDRESS_OFFSET + 8].try_into().unwrap()), PC);
    assert_eq!(field32(&record, COUNT_OFFSET), 2);
    assert_eq!(parameters(&record, 0), WRITE_FAULT);
    assert_eq!(parameters(&record, 1), ADDR);
    assert_eq!(parameters(&record, 2), 0);
    // The nested-record link must stay null: a hardware trap has no parent.
    assert_eq!(&record[0x08..0x10], &[0; 8]);
    assert!(super::super::exception_record_header_valid(&record));
}

#[test]
fn a_breakpoint_record_names_the_trapping_byte_not_the_return_address() {
    let raised = x86_64::trap(hal::fault_class::x86_64::TRAP_BP, PC).unwrap();
    assert_eq!(raised.code, STATUS_BREAKPOINT);
    assert_eq!(raised.address, PC - 1);
    assert_eq!(raised.count, 1);
    assert_eq!(x86_64::trap(hal::fault_class::x86_64::TRAP_BP, 0), None);
}

#[test]
fn each_named_x86_trap_maps_to_its_windows_status() {
    use hal::fault_class::x86_64 as fc;
    for (vec, code) in [(fc::TRAP_DE, STATUS_INTEGER_DIVIDE_BY_ZERO),
                        (fc::TRAP_DB, STATUS_SINGLE_STEP),
                        (fc::TRAP_OF, STATUS_INTEGER_OVERFLOW),
                        (fc::TRAP_BR, STATUS_ARRAY_BOUNDS_EXCEEDED),
                        (fc::TRAP_UD, STATUS_ILLEGAL_INSTRUCTION),
                        (fc::TRAP_SS, STATUS_STACK_OVERFLOW),
                        (fc::TRAP_AC, STATUS_DATATYPE_MISALIGNMENT),
                        (fc::TRAP_MF, STATUS_FLOAT_INVALID_OPERATION),
                        (fc::TRAP_XF, STATUS_FLOAT_INVALID_OPERATION)] {
        assert_eq!(x86_64::trap(vec, PC).unwrap().code, code, "vector {vec}");
    }
}

#[test]
fn a_protection_fault_reports_no_linear_address() {
    use hal::fault_class::x86_64 as fc;
    for vec in [fc::TRAP_GP, fc::TRAP_NP] {
        let raised = x86_64::trap(vec, PC).unwrap();
        assert_eq!(raised.code, STATUS_ACCESS_VIOLATION);
        assert_eq!(raised.count, 2);
        assert_eq!(raised.parameters[0], READ_FAULT);
        assert_eq!(raised.parameters[1], NO_FAULT_ADDRESS);
    }
}

#[test]
fn a_trap_with_no_windows_exception_falls_back_to_the_signal_path() {
    // #NM, #TS and the machine check have no runtime-describable exception.
    assert_eq!(x86_64::trap(hal::fault_class::x86_64::TRAP_NM, PC), None);
    assert_eq!(x86_64::trap(hal::fault_class::x86_64::TRAP_TS, PC), None);
    assert_eq!(x86_64::trap(18, PC), None);
}

fn esr(ec: u64, iss: u64) -> u64 { (ec << 26) | iss }

#[test]
fn an_arm_data_abort_reports_read_or_write_from_the_write_not_read_bit() {
    use hal::fault_class::aarch64 as fc;
    let read = aarch64::abort(esr(fc::EC_DABT_LOW, 0x07), ADDR, PC);
    assert_eq!(read.code, STATUS_ACCESS_VIOLATION);
    assert_eq!(read.parameters[0], READ_FAULT);
    assert_eq!(read.parameters[1], ADDR);
    let write = aarch64::abort(esr(fc::EC_DABT_LOW, 0x47), ADDR, PC);
    assert_eq!(write.parameters[0], WRITE_FAULT);
}

#[test]
fn an_arm_instruction_abort_reports_the_execute_access_whatever_the_write_bit_says() {
    use hal::fault_class::aarch64 as fc;
    let raised = aarch64::abort(esr(fc::EC_IABT_LOW, 0x47), ADDR, PC);
    assert_eq!(raised.parameters[0], EXECUTE_FAULT);
}

#[test]
fn each_named_arm_exception_class_maps_to_its_windows_status() {
    use hal::fault_class::aarch64 as fc;
    for (ec, code) in [(fc::EC_UNKNOWN, STATUS_ILLEGAL_INSTRUCTION),
                       (fc::EC_ILLEGAL_STATE, STATUS_ILLEGAL_INSTRUCTION),
                       (fc::EC_FP_ACCESS, STATUS_ILLEGAL_INSTRUCTION),
                       (fc::EC_PC_ALIGN, STATUS_DATATYPE_MISALIGNMENT),
                       (fc::EC_SP_ALIGN, STATUS_DATATYPE_MISALIGNMENT),
                       (fc::EC_FP_EXC, STATUS_FLOAT_INVALID_OPERATION),
                       (fc::EC_BRK, STATUS_BREAKPOINT),
                       (fc::EC_SOFTSTEP_LOW, STATUS_SINGLE_STEP),
                       (fc::EC_BREAKPT_LOW, STATUS_ILLEGAL_INSTRUCTION),
                       (fc::EC_WATCHPT_LOW, STATUS_ILLEGAL_INSTRUCTION)] {
        assert_eq!(aarch64::sync(esr(ec, 0), ADDR, PC).unwrap().code, code, "ec {ec:#x}");
    }
    // A class with no Windows exception falls back to the signal path.
    assert_eq!(aarch64::sync(esr(0x18, 0), ADDR, PC), None);
}

#[test]
fn an_arm_breakpoint_record_names_the_trapping_instruction() {
    use hal::fault_class::aarch64 as fc;
    let raised = aarch64::sync(esr(fc::EC_BRK, 0xf000), ADDR, PC).unwrap();
    assert_eq!(raised.address, PC);
    assert_eq!(raised.count, 1);
}
