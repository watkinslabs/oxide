use super::*;

fn call(ordinal: u64, args: &[u64]) -> Option<Call> { decode(ordinal, args) }

#[test]
fn every_ordinal_this_family_owns_declares_its_windows_argument_count() {
    for (ordinal, count) in CALLS { assert_eq!(argument_count(*ordinal), Some(*count), "ordinal {ordinal:#x}"); }
    assert_eq!(argument_count(0x1234), None);
    assert!(CALLS.iter().all(|entry| entry.1 <= MAX_ARGUMENTS));
}

#[test]
fn the_calls_the_reference_answers_without_state_report_their_own_constant() {
    assert_eq!(call(CANCEL_DC, &[7]), Some(Call::Constant(1)));
    assert_eq!(call(FLUSH, &[]), Some(Call::Constant(1)));
    assert_eq!(call(GET_COLOR_ADJUSTMENT, &[7, 0x2000]), Some(Call::Constant(0)));
    assert_eq!(call(SET_COLOR_ADJUSTMENT, &[7, 0x2000]), Some(Call::Constant(0)));
    assert_eq!(call(GET_DEVICE_GAMMA_RAMP, &[7, 0x2000]), Some(Call::Constant(1)));
    assert_eq!(call(SET_DEVICE_GAMMA_RAMP, &[7, 0x2000]), Some(Call::Constant(0)));
    assert_eq!(call(DESCRIBE_PIXEL_FORMAT, &[7, 1, 40, 0x2000]), Some(Call::Constant(0)));
    assert_eq!(call(SWAP_BUFFERS, &[7]), Some(Call::Constant(0)));
}

#[test]
fn a_handle_wider_than_a_gdi_slot_is_refused_but_still_consumes_the_ordinal() {
    assert_eq!(call(SAVE_DC, &[0x1_0000_0000]), None);
    let mut ran = false;
    assert_eq!(route(SAVE_DC, &[0x1_0000_0000], |_| { ran = true; 5 }), Some(0));
    assert!(!ran, "an inadmissible handle must not reach the owner");
    // The layout query reports the GDI error sentinel instead of zero.
    assert_eq!(route(SET_LAYOUT, &[0x1_0000_0000, 0, 0], |_| 5), Some(u64::from(ipc::win32_gdi::GDI_ERROR)));
    assert_eq!(route(0x1234, &[0], |_| 5), None);
}

#[test]
fn the_restore_level_is_a_signed_thirty_two_bit_value() {
    assert_eq!(call(RESTORE_DC, &[7, 0xffff_ffff_ffff_ffff]), Some(Call::RestoreDc { dc: 7, level: -1 }));
    assert_eq!(call(RESTORE_DC, &[7, 3]), Some(Call::RestoreDc { dc: 7, level: 3 }));
}

#[test]
fn the_layout_call_reads_its_layout_from_the_third_argument_not_the_second() {
    // The second argument is the width-of-extent hint, which the reference ignores.
    assert_eq!(call(SET_LAYOUT, &[7, 0x1234, 1]), Some(Call::SetLayout { dc: 7, layout: 1 }));
}

#[test]
fn the_bounds_calls_keep_their_rectangle_pointer_at_full_width() {
    assert_eq!(call(GET_BOUNDS_RECT, &[7, 0x1_0000_2000, 1]),
        Some(Call::GetBoundsRect { dc: 7, rect: 0x1_0000_2000, flags: 1 }));
    assert_eq!(call(SET_BOUNDS_RECT, &[7, 0, 4]), Some(Call::SetBoundsRect { dc: 7, rect: 0, flags: 4 }));
}

#[test]
fn the_miter_limit_arrives_as_a_raw_float_bit_pattern() {
    let bits = 2.5f32.to_bits();
    assert_eq!(call(SET_MITER_LIMIT, &[7, u64::from(bits), 0x3000]),
        Some(Call::SetMiterLimit { dc: 7, limit_bits: bits, previous: 0x3000 }));
    assert_eq!(call(GET_MITER_LIMIT, &[7, 0x3000]), Some(Call::GetMiterLimit { dc: 7, limit: 0x3000 }));
}

#[test]
fn the_client_object_type_is_a_full_dword_and_its_handle_a_gdi_slot() {
    assert_eq!(call(CREATE_CLIENT_OBJ, &[0x0046_0000]), Some(Call::CreateClientObj { kind: 0x0046_0000 }));
    assert_eq!(call(DELETE_CLIENT_OBJ, &[0x0046_0040]), Some(Call::DeleteClientObj { handle: 0x0046_0040 }));
    assert_eq!(call(DELETE_CLIENT_OBJ, &[0x1_0000_0000]), None);
}

#[test]
fn the_extended_pen_reads_its_style_array_from_the_seventh_and_eighth_arguments() {
    let args = [0x0001_0007, 5, 0, 0x00ff_0000, 0, 0, 3, 0x1_0000_4000, 0, 0, 0];
    assert_eq!(call(EXT_CREATE_PEN, &args), Some(Call::ExtCreatePen {
        style: 0x0001_0007, width: 5, brush_style: 0, color: 0x00ff_0000,
        style_count: 3, style_bits: 0x1_0000_4000 }));
    // A truncated argument list decodes nothing rather than reading past its end.
    assert_eq!(call(EXT_CREATE_PEN, &args[..6]), None);
}

#[test]
fn the_pixel_format_is_a_signed_integer() {
    assert_eq!(call(SET_PIXEL_FORMAT, &[7, 0xffff_ffff]), Some(Call::SetPixelFormat { dc: 7, format: -1 }));
}
