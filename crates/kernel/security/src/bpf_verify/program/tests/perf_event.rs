//! Perf-event program context and return contract.

use super::*;

const PE: u32 = uapi::prog_type::PERF_EVENT;
const LDX_B: u8 = 0x71;
const LDX_H: u8 = 0x69;
const LDX_W: u8 = 0x61;
const LDX_DW: u8 = 0x79;
const STX_DW: u8 = 0x7b;
const MOV_IMM: u8 = 0xb7;
const EXIT: u8 = 0x95;

fn verify_pe(insns: &[u8]) -> Result<bool, VerifyError> {
    verify_program(PE, 0, insns, &[])
}

fn read(opcode: u8, offset: usize) -> alloc::vec::Vec<u8> {
    cat(&[
        raw(opcode, 0, 1, offset as i16, 0),
        raw(EXIT, 0, 0, 0, 0),
    ])
}

#[test]
fn architecture_layouts_match_the_linux_uapi() {
    use context::perf_event_data as pe;
    assert_eq!(pe::X86_64_REGS_BYTES, 168);
    assert_eq!(pe::AARCH64_REGS_BYTES, 272);
    assert_eq!(pe::SAMPLE_PERIOD, pe::REGS_BYTES);
    assert_eq!(pe::ADDR, pe::REGS_BYTES + 8);
    assert_eq!(pe::SIZE, pe::REGS_BYTES + 16);
}

#[test]
fn register_slots_are_read_as_native_words() {
    use context::perf_event_data as pe;
    for offset in [0, pe::REGS_BYTES - pe::WORD] {
        assert_eq!(verify_pe(&read(LDX_DW, offset)), Ok(false), "offset {offset}");
    }
    assert_eq!(
        verify_pe(&read(LDX_W, pe::REGS_BYTES - pe::WORD)),
        Err(VerifyError::UnsafeContextAccess),
    );
}

#[test]
fn sample_period_and_address_admit_aligned_narrow_reads() {
    use context::perf_event_data as pe;
    for (opcode, size) in [(LDX_B, 1), (LDX_H, 2), (LDX_W, 4), (LDX_DW, 8)] {
        for field in [pe::SAMPLE_PERIOD, pe::ADDR] {
            assert_eq!(verify_pe(&read(opcode, field + pe::WORD - size)), Ok(false));
        }
    }
}

#[test]
fn misaligned_cross_field_and_past_end_reads_are_refused() {
    use context::perf_event_data as pe;
    for p in [
        read(LDX_DW, pe::SAMPLE_PERIOD + 4),
        read(LDX_DW, pe::ADDR - 4),
        read(LDX_B, pe::SIZE),
    ] {
        assert_eq!(verify_pe(&p), Err(VerifyError::UnsafeContextAccess));
    }
}

#[test]
fn the_whole_context_is_read_only() {
    use context::perf_event_data as pe;
    for offset in [0, pe::SAMPLE_PERIOD, pe::ADDR] {
        let p = cat(&[
            raw(MOV_IMM, 2, 0, 0, 1),
            raw(STX_DW, 1, 2, offset as i16, 0),
            raw(MOV_IMM, 0, 0, 0, 0),
            raw(EXIT, 0, 0, 0, 0),
        ]);
        assert_eq!(verify_pe(&p), Err(VerifyError::UnsafeContextAccess));
    }
}

#[test]
fn the_ignored_return_value_is_not_boolean_constrained() {
    let p = cat(&[
        raw(MOV_IMM, 0, 0, 0, 0x1234),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_pe(&p), Ok(false));
}
