use super::*;

const TYPE_WITH_NO_MASK: u32 = 0x14;
const TYPE_PAST_LAST: u32 = 0x20;
const TYPE_ABSURD: u32 = 0xdead_beef;

#[test]
fn mask_counts_match_the_uapi_code_space_of_each_type() {
    assert_eq!(mask_cnt(u32::from(EV_SYN)), EV_CNT);
    assert_eq!(mask_cnt(u32::from(EV_KEY)), KEY_CNT);
    assert_eq!(mask_cnt(u32::from(EV_REL)), REL_CNT);
    assert_eq!(mask_cnt(u32::from(EV_ABS)), ABS_CNT);
    assert_eq!(mask_cnt(u32::from(EV_MSC)), MSC_CNT);
    assert_eq!(mask_cnt(u32::from(EV_SW)), SW_CNT);
    assert_eq!(mask_cnt(u32::from(EV_LED)), LED_CNT);
    assert_eq!(mask_cnt(u32::from(EV_SND)), SND_CNT);
    assert_eq!(mask_cnt(u32::from(EV_FF)), FF_CNT);
}

#[test]
fn types_outside_the_maskable_set_carry_no_mask() {
    assert_eq!(mask_cnt(TYPE_WITH_NO_MASK), 0);
    assert_eq!(mask_cnt(u32::from(input::EV_PWR)), 0);
    assert_eq!(mask_cnt(TYPE_PAST_LAST), 0);
    assert_eq!(mask_cnt(TYPE_ABSURD), 0);
}

#[test]
fn largest_mask_fits_the_no_allocation_transfer_buffer() {
    for t in 0..=TYPE_PAST_LAST {
        assert!(mask_storage_bytes(mask_cnt(t)) <= MASK_MAX_BYTES);
    }
    assert_eq!(MASK_MAX_BYTES, KEY_CNT / 8);
}

#[test]
fn read_direction_truncates_a_short_buffer_instead_of_failing() {
    const SHORT: u32 = 4;
    let cnt = mask_cnt(u32::from(EV_KEY));
    let plan = plan_get(cnt, SHORT);
    assert_eq!(plan.payload, SHORT as usize);
    assert_eq!(plan.tail_len, 0);
    assert_eq!(get_copy_len(cnt, plan), SHORT as usize);
}

#[test]
fn read_direction_zeroes_the_buffer_past_the_mask() {
    const OVERSIZED: u32 = 4096;
    let cnt = mask_cnt(u32::from(EV_REL));
    let plan = plan_get(cnt, OVERSIZED);
    assert_eq!(plan.payload, MASK_WORD_BYTES);
    assert_eq!(plan.tail_off, MASK_WORD_BYTES);
    assert_eq!(plan.tail_len, OVERSIZED as usize - MASK_WORD_BYTES);
}

#[test]
fn read_direction_on_an_unmaskable_type_zeroes_the_whole_buffer() {
    const REQUESTED: u32 = 32;
    let plan = plan_get(mask_cnt(TYPE_WITH_NO_MASK), REQUESTED);
    assert_eq!(plan.payload, 0);
    assert_eq!(plan.tail_off, 0);
    assert_eq!(plan.tail_len, REQUESTED as usize);
}

#[test]
fn read_direction_accepts_a_zero_length_buffer() {
    let plan = plan_get(mask_cnt(u32::from(EV_KEY)), 0);
    assert_eq!(plan, GetMaskPlan { payload: 0, tail_off: 0, tail_len: 0 });
}

#[test]
fn write_direction_requires_whole_mask_words() {
    let cnt = mask_cnt(u32::from(EV_KEY));
    for bad in [1u32, 2, 3, 4, 7, 9, 63, 65] {
        assert_eq!(plan_set(cnt, bad), SetMaskPlan::Misaligned, "codes_size {bad}");
    }
    assert_eq!(plan_set(cnt, 0), SetMaskPlan::Copy(0));
    assert_eq!(plan_set(cnt, 8), SetMaskPlan::Copy(8));
}

#[test]
fn write_direction_clamps_an_oversized_buffer_to_the_mask_width() {
    const OVERSIZED: u32 = 4096;
    let cnt = mask_cnt(u32::from(EV_SW));
    assert_eq!(plan_set(cnt, OVERSIZED), SetMaskPlan::Copy(MASK_WORD_BYTES));
}

#[test]
fn write_direction_ignores_an_unmaskable_type_even_when_misaligned() {
    assert_eq!(plan_set(mask_cnt(TYPE_WITH_NO_MASK), 3), SetMaskPlan::Ignore);
    assert_eq!(plan_set(mask_cnt(TYPE_ABSURD), 0), SetMaskPlan::Ignore);
}

#[test]
fn descriptor_decodes_the_three_abi_fields_in_order() {
    let mut raw = [0u8; INPUT_MASK_BYTES];
    raw[0..4].copy_from_slice(&0x0000_0001u32.to_le_bytes());
    raw[4..8].copy_from_slice(&0x0000_0060u32.to_le_bytes());
    raw[8..16].copy_from_slice(&0x0000_7fff_1234_5678u64.to_le_bytes());
    assert_eq!(
        parse_input_mask(&raw),
        InputMask { ev_type: 1, codes_size: 0x60, codes_ptr: 0x0000_7fff_1234_5678 },
    );
}

#[test]
fn a_client_with_no_masks_filters_nothing() {
    let masks = EvdevMasks::new();
    assert!(!masks.any());
    assert!(!masks.is_filtered(EV_KEY, 30));
    assert!(!masks.is_filtered(EV_REL, 0));
    assert!(!masks.is_filtered(EV_SYN, input::SYN_REPORT));
}

#[test]
fn a_code_mask_admits_only_its_set_bits() {
    const KEY_A: u16 = 30;
    const KEY_B: u16 = 48;
    let mut masks = EvdevMasks::new();
    let mut bits = [0u8; 96];
    bits[usize::from(KEY_A) / 8] |= 1 << (KEY_A % 8);
    assert!(masks.set(u32::from(EV_KEY), &bits));
    assert!(masks.any());
    assert!(!masks.is_filtered(EV_KEY, KEY_A));
    assert!(masks.is_filtered(EV_KEY, KEY_B));
}

#[test]
fn a_code_past_the_mask_width_is_never_filtered() {
    let mut masks = EvdevMasks::new();
    assert!(masks.set(u32::from(EV_REL), &[0u8; 8]));
    assert!(masks.is_filtered(EV_REL, (REL_CNT - 1) as u16));
    assert!(!masks.is_filtered(EV_REL, REL_CNT as u16));
}

#[test]
fn the_type_mask_gates_whole_types_and_never_gates_sync() {
    let mut masks = EvdevMasks::new();
    let mut bits = [0u8; 8];
    bits[usize::from(EV_REL) / 8] |= 1 << (EV_REL % 8);
    assert!(masks.set(u32::from(EV_SYN), &bits));
    assert!(!masks.is_filtered(EV_REL, 0));
    assert!(masks.is_filtered(EV_KEY, 30));
    assert!(!masks.is_filtered(EV_SYN, input::SYN_REPORT));
}

#[test]
fn the_type_mask_gates_a_type_that_has_no_code_mask_of_its_own() {
    let mut masks = EvdevMasks::new();
    assert!(masks.set(u32::from(EV_SYN), &[0u8; 8]));
    // Type 0x14 has no code mask, but the type mask still applies to it.
    assert!(masks.is_filtered(TYPE_WITH_NO_MASK as u16, 0));
    // A type past the mask's own width is outside the masking system entirely.
    assert!(!masks.is_filtered(TYPE_PAST_LAST as u16, 0));
}

#[test]
fn setting_a_mask_replaces_the_previous_one_rather_than_merging() {
    const FIRST: u16 = 1;
    const SECOND: u16 = 2;
    let mut masks = EvdevMasks::new();
    let mut bits = [0u8; 8];
    bits[0] |= 1 << FIRST;
    assert!(masks.set(u32::from(EV_REL), &bits));
    let mut other = [0u8; 8];
    other[0] |= 1 << SECOND;
    assert!(masks.set(u32::from(EV_REL), &other));
    assert!(masks.is_filtered(EV_REL, FIRST));
    assert!(!masks.is_filtered(EV_REL, SECOND));
}

#[test]
fn a_short_write_leaves_the_uncovered_codes_cleared() {
    const HIGH_KEY: u16 = 400;
    let mut masks = EvdevMasks::new();
    assert!(masks.set(u32::from(EV_KEY), &[0xffu8; 8]));
    assert_eq!(masks.get(u32::from(EV_KEY)).map(<[u8]>::len), Some(MASK_MAX_BYTES));
    assert!(!masks.is_filtered(EV_KEY, 30));
    assert!(masks.is_filtered(EV_KEY, HIGH_KEY));
}

#[test]
fn an_unmaskable_type_cannot_hold_a_mask() {
    let mut masks = EvdevMasks::new();
    assert!(!masks.set(TYPE_WITH_NO_MASK, &[0xffu8; 8]));
    assert!(!masks.set(TYPE_ABSURD, &[0xffu8; 8]));
    assert!(!masks.any());
}
