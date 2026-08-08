//! Socket-filter admission contract.
//!
//! The reject cases carry the weight here: a verifier that admits
//! everything satisfies every accept case, so each accepted shape is paired
//! with the nearest shape that must be refused.

use super::*;

const SF: u32 = uapi::prog_type::SOCKET_FILTER;

// Opcode slots used below.
const LDX_W: u8 = 0x61;
const LDX_B: u8 = 0x71;
const LDX_DW: u8 = 0x79;
const STX_W: u8 = 0x63;
const ST_W: u8 = 0x62;
const MOV_IMM: u8 = 0xb7;
const MOV_REG: u8 = 0xbf;
const ADD_IMM: u8 = 0x07;
const JNE_IMM: u8 = 0x55;
const CALL: u8 = 0x85;
const EXIT: u8 = 0x95;
const LD_IMM_DW: u8 = 0x18;

fn verify_sf(insns: &[u8]) -> Result<bool, VerifyError> {
    verify_program(SF, 0, insns, &[])
}

#[test]
fn reads_the_skb_length_field_the_runner_publishes() {
    let p = cat(&[raw(LDX_W, 0, 1, context::sk_buff::LEN as i16, 0), raw(EXIT, 0, 0, 0, 0)]);
    assert_eq!(verify_sf(&p), Ok(false));
}

#[test]
fn reads_protocol_and_ifindex() {
    for field in [context::sk_buff::PROTOCOL, context::sk_buff::IFINDEX] {
        let p = cat(&[raw(LDX_W, 0, 1, field as i16, 0), raw(EXIT, 0, 0, 0, 0)]);
        assert_eq!(verify_sf(&p), Ok(false), "field {field}");
    }
}

#[test]
fn admits_a_narrow_read_inside_a_published_word() {
    let p = cat(&[raw(LDX_B, 0, 1, 1, 0), raw(EXIT, 0, 0, 0, 0)]);
    assert_eq!(verify_sf(&p), Ok(false));
}

#[test]
fn refuses_a_field_the_runner_does_not_publish() {
    // `mark` is a legal socket-filter field that this kernel has no source
    // for; it is refused at load rather than read back as a zero.
    let p = cat(&[
        raw(LDX_W, 0, 1, context::sk_buff::MARK as i16, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_sf(&p), Err(VerifyError::UnsafeContextAccess));
}

#[test]
fn refuses_the_direct_packet_pointer_fields() {
    for field in [
        context::sk_buff::DATA, context::sk_buff::DATA_END,
        context::sk_buff::DATA_META, context::sk_buff::TC_CLASSID,
    ] {
        let p = cat(&[raw(LDX_W, 0, 1, field as i16, 0), raw(EXIT, 0, 0, 0, 0)]);
        assert_eq!(verify_sf(&p), Err(VerifyError::UnsafeContextAccess), "field {field}");
    }
}

#[test]
fn refuses_the_socket_address_block() {
    for field in [
        context::sk_buff::FAMILY, context::sk_buff::REMOTE_IP4,
        context::sk_buff::LOCAL_IP6, context::sk_buff::LOCAL_PORT,
    ] {
        let p = cat(&[raw(LDX_W, 0, 1, field as i16, 0), raw(EXIT, 0, 0, 0, 0)]);
        assert_eq!(verify_sf(&p), Err(VerifyError::UnsafeContextAccess), "field {field}");
    }
}

#[test]
fn refuses_a_misaligned_context_read() {
    let p = cat(&[raw(LDX_W, 0, 1, 2, 0), raw(EXIT, 0, 0, 0, 0)]);
    assert_eq!(verify_sf(&p), Err(VerifyError::UnsafeContextAccess));
}

#[test]
fn refuses_context_arithmetic_that_leaves_the_published_window() {
    let p = cat(&[
        raw(ADD_IMM, 1, 0, 0, context::SK_FILTER_CONTEXT_BYTES as i32),
        raw(LDX_W, 0, 1, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_sf(&p), Err(VerifyError::UnsafeContextAccess));
}

#[test]
fn the_control_block_is_the_only_writable_region() {
    let write_cb = cat(&[
        raw(MOV_IMM, 2, 0, 0, 1),
        raw(STX_W, 1, 2, context::sk_buff::CB as i16, 0),
        raw(LDX_W, 0, 1, context::sk_buff::CB as i16, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_sf(&write_cb), Ok(false));

    let write_len = cat(&[
        raw(MOV_IMM, 2, 0, 0, 1),
        raw(STX_W, 1, 2, context::sk_buff::LEN as i16, 0),
        raw(MOV_IMM, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_sf(&write_len), Err(VerifyError::UnsafeContextAccess));
}

#[test]
fn a_write_past_the_end_of_the_control_block_is_refused() {
    let p = cat(&[
        raw(MOV_IMM, 2, 0, 0, 1),
        raw(STX_W, 1, 2, (context::sk_buff::CB_END - 2) as i16, 0),
        raw(MOV_IMM, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_sf(&p), Err(VerifyError::UnsafeContextAccess));
}

#[test]
fn the_exit_register_must_be_a_readable_scalar() {
    assert_eq!(verify_sf(&cat(&[raw(EXIT, 0, 0, 0, 0)])), Err(VerifyError::UninitializedReg));
    let leak = cat(&[raw(MOV_REG, 0, 1, 0, 0), raw(EXIT, 0, 0, 0, 0)]);
    assert_eq!(verify_sf(&leak), Err(VerifyError::UnsupportedOpcode));
}

#[test]
fn a_socket_filter_return_carries_no_range_but_a_cgroup_one_does() {
    // The exit value is a byte count, so every value is legal here; the
    // same program is out of contract for a cgroup ingress hook.
    let p = cat(&[raw(MOV_IMM, 0, 0, 0, 0xffff), raw(EXIT, 0, 0, 0, 0)]);
    assert_eq!(verify_sf(&p), Ok(false));
    assert_eq!(
        verify_program(uapi::prog_type::CGROUP_SKB,
            uapi::attach_type::CGROUP_INET_INGRESS, &p, &[]),
        Err(VerifyError::UnsupportedOpcode),
    );
}

#[test]
fn packet_bytes_arrive_through_the_load_helper_not_a_raw_pointer() {
    let p = cat(&[
        raw(MOV_REG, 3, 10, 0, 0),
        raw(ADD_IMM, 3, 0, 0, -8),
        raw(MOV_IMM, 2, 0, 0, 0),
        raw(MOV_IMM, 4, 0, 0, 8),
        raw(CALL, 0, 0, 0, uapi::func_id::SKB_LOAD_BYTES as i32),
        raw(LDX_DW, 0, 10, -8, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_sf(&p), Ok(false));

    // The legacy absolute packet load has no runner and must not verify.
    let abs = cat(&[raw(0x20, 0, 0, 0, 0), raw(EXIT, 0, 0, 0, 0)]);
    assert_eq!(verify_sf(&abs), Err(VerifyError::UnsupportedOpcode));
}

#[test]
fn an_unwritten_stack_slot_cannot_be_read() {
    let p = cat(&[raw(LDX_DW, 0, 10, -8, 0), raw(EXIT, 0, 0, 0, 0)]);
    assert_eq!(verify_sf(&p), Err(VerifyError::UninitializedStack));
}

#[test]
fn only_helpers_in_this_types_proto_table_are_reachable() {
    let coarse = cat(&[
        raw(CALL, 0, 0, 0, uapi::func_id::KTIME_GET_COARSE_NS as i32),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_sf(&coarse), Ok(false));

    // A cgroup sockaddr helper is out of a socket filter's proto table.
    let retval = cat(&[
        raw(CALL, 0, 0, 0, uapi::func_id::GET_RETVAL as i32),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_sf(&retval), Err(VerifyError::UnsupportedOpcode));
}

#[test]
fn an_unproved_backward_cycle_is_refused() {
    let p = cat(&[raw(0x05, 0, 0, -1, 0), raw(EXIT, 0, 0, 0, 0)]);
    assert_eq!(verify_sf(&p), Err(VerifyError::UnsupportedOpcode));
}

#[test]
fn a_map_value_pointer_must_be_null_checked_before_it_is_read() {
    let map = array(4, 1, 0);
    let maps = [map];
    let checked = cat(&[
        raw(ST_W, 10, 0, -4, 0),
        raw(MOV_REG, 2, 10, 0, 0),
        raw(ADD_IMM, 2, 0, 0, -4),
        raw(LD_IMM_DW, 1, uapi::pseudo::MAP_FD, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(CALL, 0, 0, 0, uapi::func_id::MAP_LOOKUP_ELEM as i32),
        raw(JNE_IMM, 0, 0, 1, 0),
        raw(EXIT, 0, 0, 0, 0),
        raw(LDX_W, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_program(SF, 0, &checked, &maps), Ok(false));

    let unchecked = cat(&[
        raw(ST_W, 10, 0, -4, 0),
        raw(MOV_REG, 2, 10, 0, 0),
        raw(ADD_IMM, 2, 0, 0, -4),
        raw(LD_IMM_DW, 1, uapi::pseudo::MAP_FD, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(CALL, 0, 0, 0, uapi::func_id::MAP_LOOKUP_ELEM as i32),
        raw(LDX_W, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(
        verify_program(SF, 0, &unchecked, &maps),
        Err(VerifyError::UnsafeContextAccess),
    );
}

#[test]
fn a_lookup_key_must_be_a_written_stack_slice() {
    let map = array(4, 1, 0);
    let maps = [map];
    let unwritten = cat(&[
        raw(MOV_REG, 2, 10, 0, 0),
        raw(ADD_IMM, 2, 0, 0, -4),
        raw(LD_IMM_DW, 1, uapi::pseudo::MAP_FD, 0, 0),
        raw(0, 0, 0, 0, 0),
        raw(CALL, 0, 0, 0, uapi::func_id::MAP_LOOKUP_ELEM as i32),
        raw(MOV_IMM, 0, 0, 0, 0),
        raw(EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(
        verify_program(SF, 0, &unwritten, &maps),
        Err(VerifyError::UninitializedStack),
    );
}
