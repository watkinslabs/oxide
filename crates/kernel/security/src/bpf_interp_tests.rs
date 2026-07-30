use super::*;
use alloc::vec::Vec;

fn raw(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let off_le = off.to_le_bytes();
    let imm_le = imm.to_le_bytes();
    [opc, (src << 4) | (dst & 0x0f), off_le[0], off_le[1], imm_le[0], imm_le[1], imm_le[2], imm_le[3]]
}

fn cat(parts: &[[u8; 8]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(parts.len() * 8);
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

#[test]
fn mov_imm_then_exit_returns_imm() {
    let p = cat(&[raw(0xb7, 0, 0, 0, 42), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), Some(42));
}

#[test]
fn add_imm_accumulates() {
    let p = cat(&[raw(0xb7, 0, 0, 0, 1), raw(0x07, 0, 0, 0, 41), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), Some(42));
}

#[test]
fn mov_reg_copies_register() {
    let p = cat(&[raw(0xb7, 1, 0, 0, 7), raw(0xbf, 0, 1, 0, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), Some(7));
}

#[test]
fn jeq_imm_taken_skips() {
    let p = cat(&[raw(0xb7, 0, 0, 0, 5), raw(0x15, 0, 0, 1, 5), raw(0xb7, 0, 0, 0, 999), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), Some(5));
}

#[test]
fn jne_not_taken_falls_through() {
    let p = cat(&[raw(0xb7, 0, 0, 0, 1), raw(0x55, 0, 0, 1, 1), raw(0xb7, 0, 0, 0, 42), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), Some(42));
}

#[test]
fn ja_jumps_forward() {
    let p = cat(&[raw(0xb7, 0, 0, 0, 1), raw(0x05, 0, 0, 1, 0), raw(0xb7, 0, 0, 0, 999), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), Some(1));
}

#[test]
fn ld_imm_dw_loads_64bit() {
    let p = cat(&[
        raw(0x18, 0, 0, 0, 0xCAFEBABEu32 as i32),
        raw(0x00, 0, 0, 0, 0xDEADBEEFu32 as i32),
        raw(0x95, 0, 0, 0, 0),
    ]);
    assert_eq!(run(&p, &[]), Some(0xDEADBEEFCAFEBABEu64 as i64));
}

#[test]
fn unsupported_opcode_returns_none() {
    let p = cat(&[raw(0xff, 0, 0, 0, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), None);
}

#[test]
fn ldx_mem_b_reads_packet_byte() {
    let p = cat(&[raw(0x71, 0, 1, 2, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[0x10, 0x20, 0x30, 0x40]), Some(0x30));
}

#[test]
fn ldx_mem_w_reads_little_endian_word() {
    let p = cat(&[raw(0x61, 0, 1, 0, 0), raw(0x95, 0, 0, 0, 0)]);
    let pkt = [0x78, 0x56, 0x34, 0x12];
    assert_eq!(run(&p, &pkt), Some(0x12345678));
}

#[test]
fn ldx_mem_b_out_of_bounds_returns_none() {
    let p = cat(&[raw(0x71, 0, 1, 99, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[0x10]), None);
}

#[test]
fn ldx_from_bad_address_rejected() {
    let p = cat(&[raw(0xb7, 2, 0, 0, 0x500000), raw(0x71, 0, 2, 0, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[0x10, 0x20]), None);
}

fn helper_add(
    _state: &mut HelperState,
    a: i64,
    b: i64,
    _c: i64,
    _d: i64,
    _e: i64,
) -> i64 { a + b }
fn helper_const(
    _state: &mut HelperState,
    _a: i64,
    _b: i64,
    _c: i64,
    _d: i64,
    _e: i64,
) -> i64 { 42 }
fn helper_retval(
    state: &mut HelperState,
    a: i64,
    _b: i64,
    _c: i64,
    _d: i64,
    _e: i64,
) -> i64 {
    let old = state.retval;
    state.retval = a as i32;
    old as i64
}

#[test]
fn call_unknown_helper_returns_none() {
    let p = cat(&[raw(0xb7, 1, 0, 0, 0), raw(0x85, 0, 0, 0, 99), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), None);
}

#[test]
fn coarse_time_helper_is_a_builtin_socket_filter_helper() {
    let p = cat(&[
        raw(0x85, 0, 0, 0, crate::bpf::uapi::func_id::KTIME_GET_COARSE_NS as i32),
        raw(0x95, 0, 0, 0, 0),
    ]);
    assert!(run(&p, &[]).is_some());
}

#[test]
fn call_known_helper_stores_result_in_r0() {
    let helpers = [Helper { id: 100, f: helper_const }];
    let p = cat(&[raw(0x85, 0, 0, 0, 100), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run_with_helpers(&p, &[], &helpers), Some(42));
}

#[test]
fn call_passes_r1_r5_as_args() {
    let helpers = [Helper { id: 2, f: helper_add }];
    let p = cat(&[raw(0xb7, 1, 0, 0, 10), raw(0xb7, 2, 0, 0, 32), raw(0x85, 0, 0, 0, 2), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run_with_helpers(&p, &[], &helpers), Some(42));
}

#[test]
fn helper_state_is_shared_with_the_caller() {
    let helpers = [Helper { id: 3, f: helper_retval }];
    let p = cat(&[
        raw(0xb7, 1, 0, 0, 77),
        raw(0x85, 0, 0, 0, 3),
        raw(0x95, 0, 0, 0, 0),
    ]);
    let mut state = HelperState { retval: 12 };
    assert_eq!(run_with_helpers_and_state(&p, &[], &helpers, &mut state), Some(12));
    assert_eq!(state.retval, 77);
}

fn alu64_imm(opc: u8, a: i32, b: i32) -> Option<i64> {
    run(&cat(&[raw(0xb7, 0, 0, 0, a), raw(opc, 0, 0, 0, b), raw(0x95, 0, 0, 0, 0)]), &[])
}

#[test]
fn alu64_arith_ops() {
    assert_eq!(alu64_imm(0x27, 6, 7), Some(42));
    assert_eq!(alu64_imm(0x37, 84, 2), Some(42));
    assert_eq!(alu64_imm(0x37, 5, 0), Some(0));
    assert_eq!(alu64_imm(0x97, 17, 5), Some(2));
    assert_eq!(alu64_imm(0x97, 17, 0), Some(17));
    assert_eq!(alu64_imm(0x67, 1, 5), Some(32));
    assert_eq!(alu64_imm(0x77, 64, 2), Some(16));
    assert_eq!(alu64_imm(0xc7, -8, 1), Some(-4));
    assert_eq!(run(&cat(&[raw(0xb7, 0, 0, 0, 5), raw(0x87, 0, 0, 0, 0), raw(0x95, 0, 0, 0, 0)]), &[]), Some(-5));
}

#[test]
fn alu32_zero_extends() {
    let p = cat(&[raw(0xb7, 0, 0, 0, -1), raw(0x04, 0, 0, 0, 1), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), Some(0));
    let p2 = cat(&[raw(0xb7, 0, 0, 0, -1), raw(0x54, 0, 0, 0, -1), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p2, &[]), Some(0xFFFF_FFFF));
}

#[test]
fn endian_conversion_uses_the_encoded_width() {
    let p = cat(&[
        raw(0xb7, 0, 0, 0, 0x1234),
        raw(0xdc, 0, 0, 0, 16),
        raw(0x95, 0, 0, 0, 0),
    ]);
    assert_eq!(run(&p, &[]), Some(0x3412));
}

#[test]
fn jmp_unsigned_and_signed() {
    let jgt = cat(&[raw(0xb7, 0, 0, 0, 10), raw(0x25, 0, 0, 1, 5), raw(0xb7, 0, 0, 0, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&jgt, &[]), Some(10));
    let jsgt = cat(&[raw(0xb7, 0, 0, 0, -1), raw(0x65, 0, 0, 1, 5), raw(0xb7, 0, 0, 0, 7), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&jsgt, &[]), Some(7));
    let jset = cat(&[raw(0xb7, 0, 0, 0, 0b1010), raw(0x45, 0, 0, 1, 0b0010), raw(0xb7, 0, 0, 0, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&jset, &[]), Some(0b1010));
}

#[test]
fn jmp32_compares_low_word() {
    let p = cat(&[raw(0xb7, 0, 0, 0, 5), raw(0x16, 0, 0, 1, 5), raw(0xb7, 0, 0, 0, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), Some(5));
}

#[test]
fn stack_st_then_ldx_roundtrips() {
    let p = cat(&[raw(0x62, 10, 0, -8, 1234), raw(0x61, 0, 10, -8, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), Some(1234));
}

#[test]
fn stack_stx_reg_dw_roundtrips() {
    let p = cat(&[raw(0xb7, 1, 0, 0, 99), raw(0x7b, 10, 1, -16, 0), raw(0x79, 0, 10, -16, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), Some(99));
}

#[test]
fn stack_byte_and_halfword_roundtrip() {
    let byte = cat(&[
        raw(0x72, 10, 0, -1, 0x7a),
        raw(0x71, 0, 10, -1, 0),
        raw(0x95, 0, 0, 0, 0),
    ]);
    assert_eq!(run(&byte, &[]), Some(0x7a));
    let half = cat(&[
        raw(0x6a, 10, 0, -2, 0x7abc),
        raw(0x69, 0, 10, -2, 0),
        raw(0x95, 0, 0, 0, 0),
    ]);
    assert_eq!(run(&half, &[]), Some(0x7abc));
}

#[test]
fn store_past_stack_top_is_rejected() {
    let p = cat(&[raw(0x62, 10, 0, 8, 1), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), None);
}

#[test]
fn ldx_from_ctx_still_works() {
    let p = cat(&[raw(0x71, 0, 1, 1, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[0xaa, 0xbb, 0xcc]), Some(0xbb));
}

#[test]
fn skb_load_bytes_fault_zeroes_the_full_destination() {
    let p = cat(&[
        raw(0x62, 10, 0, -4, 0x7f7f_7f7f),
        raw(0xb7, 2, 0, 0, 99),
        raw(0xbf, 3, 10, 0, 0),
        raw(0x07, 3, 0, 0, -4),
        raw(0xb7, 4, 0, 0, 4),
        raw(0x85, 0, 0, 0, crate::bpf::uapi::func_id::SKB_LOAD_BYTES as i32),
        raw(0xbf, 6, 0, 0, 0),
        raw(0x61, 0, 10, -4, 0),
        raw(0x55, 0, 0, 1, 0),
        raw(0xbf, 0, 6, 0, 0),
        raw(0x95, 0, 0, 0, 0),
    ]);
    assert_eq!(run(&p, &[1, 2, 3]), Some(-(syscall::errno::Errno::Efault.as_i32() as i64)));
}

#[test]
fn infinite_loop_hits_step_budget() {
    let p = cat(&[raw(0x05, 0, 0, -1, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(run(&p, &[]), None);
}

#[test]
fn bounded_backward_loop_executes_to_exit() {
    let p = cat(&[
        raw(0xb7, 0, 0, 0, 0),
        raw(0xb7, 2, 0, 0, 0),
        raw(0x07, 0, 0, 0, 1),
        raw(0x07, 2, 0, 0, 1),
        raw(0xa5, 2, 0, -3, 4),
        raw(0x95, 0, 0, 0, 0),
    ]);
    assert_eq!(run(&p, &[]), Some(4));
}
