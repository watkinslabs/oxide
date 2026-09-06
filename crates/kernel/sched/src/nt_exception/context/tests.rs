use super::*;

const USER_CS: u16 = 0x33;
const USER_SS: u16 = 0x2b;
const USER_DS: u16 = 0x2b;

fn sample() -> X64Registers {
    X64Registers {
        rax: 0x01, rcx: 0x02, rdx: 0x03, rbx: 0x04,
        rsp: 0x0000_7fff_ffff_0000, rbp: 0x06, rsi: 0x07, rdi: 0x08,
        r8: 0x09, r9: 0x0a, r10: 0x0b, r11: 0x0c,
        r12: 0x0d, r13: 0x0e, r14: 0x0f, r15: 0x10,
        rip: 0x0000_7ff8_1234_5670, rflags: 0x246,
        cs: USER_CS, ss: USER_SS,
    }
}

fn q(context: &[u8], at: usize) -> u64 { u64::from_le_bytes(context[at..at + 8].try_into().unwrap()) }
fn d(context: &[u8], at: usize) -> u32 { u32::from_le_bytes(context[at..at + 4].try_into().unwrap()) }
fn w(context: &[u8], at: usize) -> u16 { u16::from_le_bytes(context[at..at + 2].try_into().unwrap()) }

#[test]
fn every_general_register_lands_at_its_context_offset() {
    let context = x64_context(&sample(), USER_DS);
    for (at, value) in [(0x78, 0x01u64), (0x80, 0x02), (0x88, 0x03), (0x90, 0x04),
                        (0x98, 0x0000_7fff_ffff_0000), (0xa0, 0x06), (0xa8, 0x07), (0xb0, 0x08),
                        (0xb8, 0x09), (0xc0, 0x0a), (0xc8, 0x0b), (0xd0, 0x0c),
                        (0xd8, 0x0d), (0xe0, 0x0e), (0xe8, 0x0f), (0xf0, 0x10),
                        (0xf8, 0x0000_7ff8_1234_5670)] {
        assert_eq!(q(&context, at), value, "offset {at:#x}");
    }
}

#[test]
fn the_frame_advertises_control_integer_and_segment_components_only() {
    let context = x64_context(&sample(), USER_DS);
    assert_eq!(d(&context, 0x30), X64_CONTEXT_FLAGS);
    // Floating-point (0x8) and debug registers (0x10) are not carried, so a
    // consumer must not be told to read them out of an untouched frame.
    assert_eq!(X64_CONTEXT_FLAGS & 0x8, 0);
    assert_eq!(X64_CONTEXT_FLAGS & 0x10, 0);
}

#[test]
fn selectors_and_flags_report_the_interrupted_thread() {
    let context = x64_context(&sample(), USER_DS);
    assert_eq!(w(&context, 0x38), USER_CS);
    assert_eq!(w(&context, 0x42), USER_SS);
    for at in [0x3a, 0x3c, 0x3e, 0x40] { assert_eq!(w(&context, at), USER_DS, "selector {at:#x}"); }
    assert_eq!(d(&context, 0x44), 0x246);
}

#[test]
fn a_published_context_passes_the_pending_validation_it_will_face() {
    let mut record = [0u8; super::super::EXCEPTION_RECORD_BYTES];
    record[0..4].copy_from_slice(&super::super::fault::STATUS_ACCESS_VIOLATION.to_le_bytes());
    let pending = super::super::Pending {
        record, context: Some(x64_context(&sample(), USER_DS)), first_chance: true,
    };
    #[cfg(target_arch = "x86_64")]
    assert!(pending.is_valid());
    let _ = pending;
}

#[test]
fn the_context_ex_chunks_locate_the_legacy_context_behind_themselves() {
    let mut frame = [0u8; X64_CONTEXT_EX_OFFSET + X64_CONTEXT_EX_BYTES];
    assert!(x64_write_context_ex(&mut frame));
    let base = X64_CONTEXT_EX_OFFSET;
    let signed = |at: usize| i32::from_le_bytes(frame[at..at + 4].try_into().unwrap());
    // All and Legacy both start one CONTEXT behind the chunk descriptors.
    assert_eq!(signed(base), -(CONTEXT_BYTES as i32));
    assert_eq!(d(&frame, base + 4), CONTEXT_BYTES as u32 + 24);
    assert_eq!(signed(base + 8), -(CONTEXT_BYTES as i32));
    assert_eq!(d(&frame, base + 12), CONTEXT_BYTES as u32);
    // No extended state: the XState chunk describes nothing at offset zero.
    assert_eq!(signed(base + 16), 0);
    assert_eq!(d(&frame, base + 20), 25);
}

#[test]
fn a_frame_too_short_for_the_chunks_is_refused_rather_than_half_written() {
    let mut frame = [0u8; X64_CONTEXT_EX_OFFSET + X64_CONTEXT_EX_BYTES - 1];
    assert!(!x64_write_context_ex(&mut frame));
    assert!(frame[X64_CONTEXT_EX_OFFSET..].iter().all(|byte| *byte == 0));
}

#[test]
fn the_dispatcher_runs_with_trap_direction_and_alignment_check_clear() {
    assert_eq!(x64_dispatch_rflags(0x246 | 0x100 | 0x400 | 0x40000), 0x246);
    // Every other flag survives, including the reserved bit the return path
    // requires and the arithmetic flags a handler may inspect.
    assert_eq!(x64_dispatch_rflags(0x8d5), 0x8d5);
}
