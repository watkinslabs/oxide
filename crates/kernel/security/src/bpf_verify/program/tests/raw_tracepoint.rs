use super::*;

#[test]
fn raw_tracepoint_reads_aligned_argument_slots_only_inside_twelve_words() {
    let good = cat(&[raw(0x79, 0, 1, 8, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(verify_program(uapi::prog_type::RAW_TRACEPOINT, 0, &good, &[]), Ok(false));

    let past = cat(&[raw(0x79, 0, 1, 96, 0), raw(0x95, 0, 0, 0, 0)]);
    assert_eq!(verify_program(uapi::prog_type::RAW_TRACEPOINT, 0, &past, &[]),
               Err(VerifyError::UnsafeContextAccess));
}

#[test]
fn raw_tracepoint_program_may_read_its_link_cookie() {
    let program = cat(&[
        raw(0x85, 0, 0, 0, uapi::func_id::GET_ATTACH_COOKIE as i32),
        raw(0x95, 0, 0, 0, 0),
    ]);
    assert_eq!(verify_program(uapi::prog_type::RAW_TRACEPOINT, 0, &program, &[]), Ok(false));
    assert_eq!(verify_program(uapi::prog_type::SOCKET_FILTER, 0, &program, &[]),
               Err(VerifyError::UnsupportedOpcode));
}

