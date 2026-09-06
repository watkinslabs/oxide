use super::*;

#[test]
fn unary_stub_preserves_windows_nonvolatile_rdi_and_moves_rcx() {
    let bytes = encode_x64_unary_stub(0x4e54_0000_0000_0006);
    assert_eq!(&bytes[..4], &[0x57, 0x48, 0x89, 0xcf]);
    assert_eq!(&bytes[4..14], &[0x48, 0xb8, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x4e]);
    assert_eq!(&bytes[14..], &[0x0f, 0x05, 0x5f, 0xc3]);
}

#[test]
fn zero_arg_stub_uses_native_selector_without_consuming_registers() {
    let bytes = encode_x64_zero_arg_stub(0x4e54_0000_0000_021d);
    assert_eq!(&bytes[0..2], &[0x48, 0xb8]);
    assert_eq!(&bytes[2..10], &0x4e54_0000_0000_021du64.to_le_bytes());
    assert_eq!(&bytes[10..], &[0x0f, 0x05, 0xc3]);
}

#[test]
fn wndproc_continuation_stores_lresult_and_calls_callback_return() {
    let bytes = encode_x64_wndproc_continuation(0x4e54_0000_0000_00da);
    assert_eq!(&bytes[..4], &[0x48, 0x89, 0x04, 0x24]);
    assert_eq!(&bytes[4..7], &[0x48, 0x89, 0xe1]);
    assert_eq!(&bytes[7..12], &[0xba, 0x08, 0x00, 0x00, 0x00]);
    assert!(bytes.windows(3).any(|window| window == [0x48, 0x89, 0xcf]));
    assert!(bytes.windows(3).any(|window| window == [0x48, 0x89, 0xd6]));
    assert!(bytes.windows(3).any(|window| window == [0x4c, 0x89, 0xc2]));
    assert!(bytes.windows(2).any(|pair| pair == [0x0f, 0x05]));
    assert_eq!(bytes.last(), Some(&0xcc));
}

#[test]
fn six_arg_stub_translates_register_and_stack_arguments() {
    let bytes = encode_x64_six_arg_stub(0x4e54_0000_0000_0000);
    assert_eq!(&bytes[..8], &[0x57, 0x56, 0x48, 0x89, 0xcf, 0x48, 0x89, 0xd6]);
    assert_eq!(&bytes[8..14], &[0x4c, 0x89, 0xc2, 0x4d, 0x89, 0xca]);
    assert_eq!(&bytes[14..19], &[0x4c, 0x8b, 0x44, 0x24, 0x38]);
    assert_eq!(&bytes[19..24], &[0x4c, 0x8b, 0x4c, 0x24, 0x40]);
    assert_eq!(&bytes[24..34], &[0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0x54, 0x4e]);
    assert_eq!(&bytes[34..], &[0x0f, 0x05, 0x5e, 0x5f, 0xc3]);
}

#[test]
fn breakpoint_stub_matches_wine_x64_entry() {
    assert_eq!(encode_x64_breakpoint_stub(), [0xcc, 0xc3]);
}

#[test]
fn relay_stub_preserves_the_wine_home_area_before_calling_target() {
    let bytes = encode_x64_relay_stub(0x4e54_0000_0000_0216);
    assert_eq!(&bytes[..15], &[0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x56, 0x57, 0x4c, 0x8d, 0x64]);
    assert_eq!(bytes.windows(5).filter(|window| *window == [0x4c, 0x8d, 0x64, 0x24, 72]).count(), 2);
    assert!(bytes.windows(5).any(|window| window == [0x49, 0x8d, 0x54, 0x24, 0]));
    assert_eq!(&bytes[38..40], &[0x0f, 0x05]);
    assert_eq!(&bytes[43..45], &[0x0f, 0x84]);
    let displacement = i32::from_le_bytes(bytes[45..49].try_into().unwrap()) as isize;
    let unresolved = (49isize + displacement) as usize;
    assert_eq!(&bytes[unresolved..unresolved + 5], &[0xb8, 0x7a, 0x00, 0x00, 0xc0]);
    assert_eq!(&bytes[49..54], &[0x4c, 0x8d, 0x64, 0x24, 72]);
    assert_eq!(&bytes[54..58], &[0x48, 0x83, 0xec, 0x60]);
    assert!(bytes.windows(5).any(|window| window == [0x4d, 0x8b, 0x54, 0x24, 0]));
    assert!(bytes.windows(3).any(|window| window == [0x48, 0x85, 0xc0]));
    assert!(bytes.windows(5).any(|window| window == [0xb8, 0x7a, 0x00, 0x00, 0xc0]));
    assert!(bytes.windows(2).any(|window| window == [0xff, 0xd0]));
    assert!(bytes.windows(4).any(|window| window == [0x48, 0x83, 0xc4, 0x60]));
    assert!(bytes.windows(3).any(|window| window == [0x41, 0x5f, 0x41]));
    assert!(bytes.windows(4).any(|window| window == [0x5d, 0x5b, 0xc3, 0xb8]));
}

#[test]
fn wine_dispatcher_copies_all_x64_arguments_and_ordinal() {
    let bytes = encode_x64_wine_dispatcher_stub(0x4e54_0000_0000_0217);
    assert!(bytes.len() > 260);
    assert!(bytes.windows(7).any(|window| window == [0x48, 0x81, 0xec, 0xb8, 0, 0, 0]));
    assert!(bytes.windows(3).any(|window| window == [0x41, 0x89, 0xc5]));
    assert!(bytes.windows(5).any(|window| window == [0x44, 0x89, 0xef, 0x48, 0x8d]));
    assert!(bytes.windows(4).any(|window| window == [0x48, 0x8d, 0x74, 0x24]));
    assert!(bytes.windows(4).any(|window| window == [0x49, 0x8b, 0x84, 0x24]));
    assert!(bytes.windows(4).any(|window| window == [0x48, 0x89, 0x84, 0x24]));
    assert!(bytes.windows(2).any(|window| window == [0x0f, 0x05]));
    assert!(bytes.windows(7).any(|window| window == [0x48, 0x81, 0xc4, 0xb8, 0, 0, 0]));
    assert_eq!(&bytes[bytes.len() - 13..], &[0x5f, 0x5e, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5d, 0x5b, 0xc3]);
}

#[test]
fn unix_call_dispatcher_translates_handle_code_and_args() {
    let bytes = encode_x64_unix_call_dispatcher_stub(0x4e54_0000_0000_0218);
    assert_eq!(&bytes[..2], &[0x57, 0x56]);
    assert!(bytes.windows(2).any(|window| window == [0x0f, 0x05]));
    assert_eq!(&bytes[bytes.len() - 3..], &[0x5e, 0x5f, 0xc3]);
}

#[test]
fn unix_call_handoff_binds_table_target_to_the_x64_return_lifecycle() {
    let call = prepare_x64_unix_call(
        0xfeed, 7, 0x7fff_0000_2000, 0x7f00_0000_4100,
        0x7fff_0000_1234, 0x7fff_0000_1ff0, 0x0000_8000_0000_0000,
    ).expect("valid Wine frame");
    assert_eq!(call.code, 7);
    assert_eq!(call.callable, 0x7f00_0000_4100);
    assert_eq!(call.return_rsp, call.syscall_rsp + X64_UNIX_CALL_RETURN_BYTES);
    assert_eq!(complete_x64_unix_call(call, 0), X64UnixCallReturn { call, status: 0 });
}

#[test]
fn native_unix_call_uses_sysv_entry_alignment_and_wine_continuation_slot() {
    assert_eq!(native_x64_call_rsp(0x7fff_0000_1ff0, 0x0000_8000_0000_0000), Some(0x7fff_0000_1fe8));
    assert_eq!(native_x64_call_rsp(0x7fff_0000_1ff8, 0x0000_8000_0000_0000), None);
    assert_eq!(native_x64_call_rsp(0, 0x0000_8000_0000_0000), None);
    assert_eq!(native_x64_call_rsp(0x2000, 0x2000), None);
    assert_eq!(native_x64_call_rsp(0x2000, 0x1ffc), None);
}

#[test]
fn unix_call_handoff_rejects_frame_and_fixed_abi_violations() {
    let end = 0x0000_8000_0000_0000;
    let valid = (0xfeed, 7, 0x2000, 0x4100, 0x1200, 0x2000);
    assert!(prepare_x64_unix_call(valid.0, valid.1, valid.2, valid.3, valid.4, valid.5, end).is_some());
    assert!(prepare_x64_unix_call(0, valid.1, valid.2, valid.3, valid.4, valid.5, end).is_none());
    assert!(prepare_x64_unix_call(valid.0, u64::from(u32::MAX) + 1, valid.2, valid.3, valid.4, valid.5, end).is_none());
    assert!(prepare_x64_unix_call(valid.0, valid.1, valid.2, valid.3, valid.4, valid.5 + 8, end).is_none());
    assert!(prepare_x64_unix_call(valid.0, valid.1, valid.2, valid.3, end, valid.5, end).is_none());
    assert!(prepare_x64_unix_call(valid.0, valid.1, valid.2, 0, valid.4, valid.5, end).is_none());
}

#[test]
fn unix_call_handoff_requires_room_for_the_entire_epilogue() {
    let prepare = |rsp, end| prepare_x64_unix_call(1, 0, 0, 0x100, 0x200, rsp, end);
    assert!(prepare(0x1000, 0x10c1).is_some());
    assert!(prepare(0x1000, 0x10c0).is_none());
    assert!(prepare(0x1000, 0x1019).is_none());
    assert!(prepare(u64::MAX - 15, u64::MAX).is_none());
}

#[test]
fn apc_continuation_restores_saved_context_and_jumps_to_rip() {
    let bytes = encode_x64_apc_continuation();
    assert_eq!(bytes.len(), 14 * 5 + 10 + 3);
    assert_eq!(&bytes[0..4], &[0x48, 0x8b, 0x44, 0x24]);
    assert!(bytes.windows(5).any(|window| window == [0x4c, 0x8b, 0x5c, 0x24, 0xa0]));
    assert!(bytes.ends_with(&[0x41, 0xff, 0xe3]));
}

#[test]
fn exception_stack_contract_matches_wine_layout_and_alignment() {
    assert_eq!(X64_EXCEPTION_CONTEXT_EX_OFFSET, 0x4d0);
    assert_eq!(X64_EXCEPTION_RECORD_OFFSET, 0x4f0);
    assert_eq!(X64_EXCEPTION_MACHINE_FRAME_OFFSET, 0x590);
    assert_eq!(X64_EXCEPTION_FRAME_BYTES, 0x5c0);
    let stack = x64_exception_stack(0x7fff_ffff_f000, 0x240);
    assert_eq!(stack, Some((0x7fff_ffff_f000 - 0x5c0 - 0x240) & !63));
    assert_eq!(x64_exception_stack(0x500, 0), None);
    let frame = x64_exception_frame(0x7fff_ffff_f000, 0x240).unwrap();
    assert_eq!(frame.context, frame.stack);
    assert_eq!(frame.exception_record - frame.stack, 0x4f0);
    assert_eq!(frame.machine_frame - frame.stack, 0x590);
    assert_eq!(x64_exception_frame(0x500, 0), None);
}

#[test]
fn exception_frame_range_is_one_writable_transaction() {
    assert!(valid_x64_exception_frame_range(0x7000, 0x6000, 0x8000, true));
    assert!(!valid_x64_exception_frame_range(0x7000, 0x6000, 0x8000, false));
    assert!(!valid_x64_exception_frame_range(0x7000, 0x6000, 0x75bf, true));
    assert!(!valid_x64_exception_frame_range(u64::MAX - 0x10, 0, u64::MAX, true));
}

#[test]
fn unwind_target_must_not_move_backwards_or_wrap() {
    assert!(valid_x64_unwind_target(0x7fff_0000_1000, 0x7fff_0000_1000));
    assert!(valid_x64_unwind_target(0x7fff_0000_1000, 0x7fff_0000_1010));
    assert!(!valid_x64_unwind_target(0x7fff_0000_1010, 0x7fff_0000_1000));
    assert!(!valid_x64_unwind_target(u64::MAX - 4, u64::MAX - 4));
}
