use super::*;

#[test]
fn every_ordinal_this_family_owns_declares_its_windows_argument_count() {
    for (ordinal, count) in CALLS { assert_eq!(argument_count(*ordinal), Some(*count), "ordinal {ordinal:#x}"); }
    assert_eq!(argument_count(0x1234), None);
    assert!(CALLS.iter().all(|entry| entry.1 <= MAX_ARGUMENTS));
}

#[test]
fn the_transform_query_keeps_its_space_selector_and_output_pointer() {
    assert_eq!(decode(GET_TRANSFORM, &[7, 0x204, 0x1_0000_5000]),
        Some(Call::GetTransform { dc: 7, which: 0x204, xform: 0x1_0000_5000 }));
}

#[test]
fn the_world_transform_admits_a_null_matrix_for_the_decoder_to_pass_on() {
    assert_eq!(decode(MODIFY_WORLD_TRANSFORM, &[7, 0, 1]),
        Some(Call::ModifyWorldTransform { dc: 7, xform: 0, mode: 1 }));
}

#[test]
fn a_point_run_is_bounded_before_any_user_memory_is_read() {
    assert_eq!(decode(TRANSFORM_POINTS, &[7, 0x1000, 0x2000, 4, 0]),
        Some(Call::TransformPoints { dc: 7, input: 0x1000, output: 0x2000, count: 4, mode: 0 }));
    assert_eq!(decode(TRANSFORM_POINTS, &[7, 0x1000, 0x2000, u64::from(MAX_POINTS as u32) + 1, 0]), None);
    // A negative count is not a very large one.
    assert_eq!(decode(TRANSFORM_POINTS, &[7, 0x1000, 0x2000, 0xffff_ffff, 0]), None);
    assert_eq!(route(TRANSFORM_POINTS, &[7, 0x1000, 0x2000, 0xffff_ffff, 0], |_| 1), Some(0));
}

#[test]
fn both_scale_calls_share_one_decoder_and_differ_only_in_their_target() {
    assert_eq!(decode(SCALE_VIEWPORT_EXT, &[7, 3, 2, 0xffff_fffe, 4, 0x6000]),
        Some(Call::ScaleExt { dc: 7, viewport: true, ratio: [3, 2, -2, 4], size: 0x6000 }));
    assert_eq!(decode(SCALE_WINDOW_EXT, &[7, 3, 2, 1, 4, 0]),
        Some(Call::ScaleExt { dc: 7, viewport: false, ratio: [3, 2, 1, 4], size: 0 }));
}

#[test]
fn the_virtual_resolution_carries_two_pairs_in_resolution_then_size_order() {
    assert_eq!(decode(SET_VIRTUAL_RESOLUTION, &[7, 1024, 768, 270, 203]),
        Some(Call::SetVirtualResolution { dc: 7, res: (1024, 768), size: (270, 203) }));
    assert_eq!(decode(SET_VIRTUAL_RESOLUTION, &[7, 0, 0, 0, 0]),
        Some(Call::SetVirtualResolution { dc: 7, res: (0, 0), size: (0, 0) }));
}

#[test]
fn the_coefficient_recomputation_carries_nothing_but_its_device_context() {
    assert_eq!(decode(COMPUTE_XFORM_COEFFICIENTS, &[7]), Some(Call::ComputeXformCoefficients { dc: 7 }));
    assert_eq!(decode(COMPUTE_XFORM_COEFFICIENTS, &[0x1_0000_0000]), None);
    assert_eq!(route(0x1234, &[7], |_| 1), None);
}
