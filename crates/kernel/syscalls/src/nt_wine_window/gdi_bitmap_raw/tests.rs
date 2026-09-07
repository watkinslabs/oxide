//! Ordinal admission and typed decode for the bitmap, blit and palette family.
use super::*;

#[test]
fn the_admission_table_is_sorted_and_names_every_ordinal_once() {
    for pair in ORDINALS.windows(2) { assert!(pair[0].0 < pair[1].0, "{:#x} then {:#x}", pair[0].0, pair[1].0); }
    assert_eq!(ORDINALS.len(), 38);
    for (ordinal, count) in ORDINALS {
        assert_eq!(argument_count(*ordinal), Some(*count));
        assert!(*count <= MAX_ARGUMENTS);
    }
    assert_eq!(argument_count(0x1096), None);
    assert_eq!(argument_count(0), None);
}

#[test]
fn every_admitted_ordinal_decodes_from_a_full_argument_list() {
    let args = [1u64; MAX_ARGUMENTS];
    for (ordinal, _) in ORDINALS { assert!(decode(*ordinal, &args).is_some(), "{ordinal:#x}"); }
    assert_eq!(decode(0x1096, &args), None);
}

#[test]
fn a_short_argument_list_decodes_nothing() {
    let args = [1u64; 4];
    assert_eq!(decode(BIT_BLT, &args), None);
    assert_eq!(decode(SET_PIXEL, &args[..3]), None);
    assert_eq!(decode(SET_PIXEL, &args), decode(SET_PIXEL, &[1, 1, 1, 1]));
}

#[test]
fn blit_rectangles_take_their_windows_parameter_order() {
    let mut args = [0u64; MAX_ARGUMENTS];
    args[..9].copy_from_slice(&[7, 1, 2, 3, 4, 9, 5, 6, 0x00cc_0020]);
    assert_eq!(decode(BIT_BLT, &args), Some(Operation::BitBlt { dst: 7,
        dst_rect: Rect { x: 1, y: 2, width: 3, height: 4 }, src: 9, src_x: 5, src_y: 6, code: 0x00cc_0020 }));
    let mut stretch = [0u64; MAX_ARGUMENTS];
    stretch[..11].copy_from_slice(&[7, 1, 2, 3, 4, 9, 5, 6, 7, 8, 0x00cc_0020]);
    assert_eq!(decode(STRETCH_BLT, &stretch), Some(Operation::StretchBlt { dst: 7,
        dst_rect: Rect { x: 1, y: 2, width: 3, height: 4 }, src: 9,
        src_rect: Rect { x: 5, y: 6, width: 7, height: 8 }, code: 0x00cc_0020 }));
}

#[test]
fn negative_scalars_survive_the_register_halves_above_them() {
    let mut args = [0u64; MAX_ARGUMENTS];
    args[..4].copy_from_slice(&[7, 0xdead_0000_ffff_fffe, 0xbeef_0000_ffff_fffd, 0x00ff_0000]);
    assert_eq!(decode(SET_PIXEL, &args), Some(Operation::SetPixel { dc: 7, x: -2, y: -3, color: 0x00ff_0000 }));
}

#[test]
fn palette_calls_narrow_their_word_sized_arguments() {
    let args = [5u64, 0x1_0002, 0x1_0003, 9, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(decode(DO_PALETTE, &args), Some(Operation::DoPalette { handle: 5, start: 2, count: 3,
        entries: 9, function: 2, inbound: true }));
    let select = [7u64, 8, 0x1_0000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(decode(SELECT_PALETTE, &select), Some(Operation::SelectPalette { dc: 7, palette: 8, background: false }));
    let foreground = [7u64, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(decode(SELECT_PALETTE, &foreground), Some(Operation::SelectPalette { dc: 7, palette: 8, background: true }));
}

#[test]
fn calls_whose_arguments_the_owner_never_consults_decode_to_a_bare_operation() {
    let args = [1u64; MAX_ARGUMENTS];
    assert_eq!(decode(DRAW_STREAM, &args), Some(Operation::DrawStream));
    assert_eq!(decode(SET_MAGIC_COLORS, &args), Some(Operation::SetMagicColors));
    assert_eq!(decode(GET_SYSTEM_PALETTE_USE, &args), Some(Operation::GetSystemPaletteUse));
    assert_eq!(decode(CREATE_HALFTONE_PALETTE, &args), Some(Operation::CreateHalftonePalette));
}

#[test]
fn collection_reads_only_the_stack_words_the_signature_names() {
    let (mut read, mut count) = ([0usize; MAX_ARGUMENTS], 0usize);
    let out = collect(BIT_BLT, [1, 2, 3, 4, 5, 6], |index| { read[count] = index; count += 1; Some(index as u64 * 10) });
    assert_eq!(&read[..count], &[6, 7, 8, 9, 10]);
    let args = out.unwrap().unwrap();
    assert_eq!(&args[..6], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(args[8], 80);
    assert_eq!(args[11], 0);
}

#[test]
fn a_signature_inside_the_registers_reads_no_stack_word_at_all() {
    let mut read = 0;
    let out = collect(SET_PIXEL, [1, 2, 3, 4, 5, 6], |_| { read += 1; Some(0) });
    assert_eq!(read, 0);
    assert_eq!(&out.unwrap().unwrap()[..4], &[1, 2, 3, 4]);
}

#[test]
fn an_unadmitted_ordinal_never_touches_the_stack_and_a_fault_fails_the_call() {
    let mut read = 0;
    assert!(collect(0x1096, [0; 6], |_| { read += 1; Some(0) }).is_none());
    assert_eq!(read, 0);
    assert_eq!(collect(BIT_BLT, [0; 6], |_| None), Some(Err(())));
}

#[test]
fn the_widest_signature_fits_the_collected_argument_list() {
    let out = collect(SET_DIBITS_TO_DEVICE, [1, 2, 3, 4, 5, 6], |index| Some(index as u64));
    let args = out.unwrap().unwrap();
    assert_eq!(args[15], 15);
    assert!(decode(SET_DIBITS_TO_DEVICE, &args).is_some());
}
