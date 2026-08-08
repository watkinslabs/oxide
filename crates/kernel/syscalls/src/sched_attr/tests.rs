// Hosted unit tests for the `struct sched_attr` extensible-struct ABI.
// Reference: Linux's `sched_copy_attr`,
// `sys_sched_getattr`, `uclamp_validate`, `__setscheduler_uclamp`,
// `copy_struct_from_user`, and `copy_struct_to_user`.

use super::*;

const EINVAL: i64 = -(Errno::Einval as i32 as i64);

// --- copy-in size ladder (sched_copy_attr) ---------------------------------

#[test]
fn zero_size_means_ver0() {
    // "ABI compatibility quirk: if (!size) size = SCHED_ATTR_SIZE_VER0".
    assert_eq!(copy_in_size(0), Ok(CopyIn { size: SIZE_VER0, copy: SIZE_VER0, tail: 0 }));
}

#[test]
fn short_struct_is_accepted_and_zero_filled() {
    let p = copy_in_size(SIZE_VER0).unwrap();
    assert_eq!(p.copy, SIZE_VER0);
    assert_eq!(p.tail, 0);
    // The kernel struct is KSIZE; the 8 unread bytes stay zero.
    assert_eq!(KSIZE - p.copy, 8);
}

#[test]
fn size_below_ver0_is_e2big_not_einval() {
    for s in 1..SIZE_VER0 { assert_eq!(copy_in_size(s), Err(()), "size {s}"); }
}

#[test]
fn size_above_page_size_is_e2big() {
    assert_eq!(copy_in_size(MAX_SIZE + 1), Err(()));
    assert_eq!(copy_in_size(u32::MAX), Err(()));
    assert!(copy_in_size(MAX_SIZE).is_ok());
}

#[test]
fn oversized_struct_copies_ksize_and_checks_the_tail() {
    // usize > ksize: copy_struct_from_user copies ksize and requires the
    // remaining (usize - ksize) user bytes to be zero, else -E2BIG.
    let p = copy_in_size(96).unwrap();
    assert_eq!(p, CopyIn { size: 96, copy: KSIZE, tail: 96 - KSIZE });
}

#[test]
fn exact_ksize_has_no_tail() {
    assert_eq!(copy_in_size(KSIZE), Ok(CopyIn { size: KSIZE, copy: KSIZE, tail: 0 }));
}

// --- copy-in post-checks ---------------------------------------------------

#[test]
fn util_clamp_needs_a_ver1_sized_struct() {
    let mut a = SchedAttr { flags: FLAG_UTIL_CLAMP_MIN, ..Default::default() };
    assert_eq!(finish_copy_in(&mut a, SIZE_VER0), Err(EINVAL));
    let mut a = SchedAttr { flags: FLAG_UTIL_CLAMP_MAX, ..Default::default() };
    assert_eq!(finish_copy_in(&mut a, SIZE_VER1), Ok(()));
}

#[test]
fn nice_is_clamped_not_rejected() {
    let mut a = SchedAttr { nice: 1000, ..Default::default() };
    assert_eq!(finish_copy_in(&mut a, SIZE_VER0), Ok(()));
    assert_eq!(a.nice, MAX_NICE);
    let mut a = SchedAttr { nice: -1000, ..Default::default() };
    assert_eq!(finish_copy_in(&mut a, SIZE_VER0), Ok(()));
    assert_eq!(a.nice, MIN_NICE);
}

// --- copy-out size ladder (sys_sched_getattr) ------------------------------

#[test]
fn getattr_rejects_out_of_range_sizes_with_einval() {
    assert_eq!(copy_out_size(0), Err(EINVAL));
    assert_eq!(copy_out_size(SIZE_VER0 - 1), Err(EINVAL));
    assert_eq!(copy_out_size(MAX_SIZE + 1), Err(EINVAL));
}

#[test]
fn getattr_short_struct_reports_the_user_size() {
    // usize < ksize: only the interoperable prefix is copied and kattr.size
    // is min(usize, sizeof(kattr)).
    assert_eq!(copy_out_size(SIZE_VER0),
               Ok(CopyOut { reported: SIZE_VER0, copy: SIZE_VER0, zero: 0 }));
}

#[test]
fn getattr_long_struct_zero_fills_the_tail() {
    // usize > ksize: clear_user() the trailing bytes so the caller never sees
    // garbage in fields this kernel does not know about.
    assert_eq!(copy_out_size(128),
               Ok(CopyOut { reported: KSIZE, copy: KSIZE, zero: 128 - KSIZE }));
}

// --- encode/decode ---------------------------------------------------------

#[test]
fn field_offsets_match_the_uapi_layout() {
    let a = SchedAttr { size: 56, policy: 1, flags: 0x40, nice: -5, priority: 42,
                        runtime: 0x1111, deadline: 0x2222, period: 0x3333,
                        util_min: 100, util_max: 900 };
    let b = a.to_bytes();
    assert_eq!(&b[0..4], &56u32.to_le_bytes());
    assert_eq!(&b[4..8], &1u32.to_le_bytes());
    assert_eq!(&b[8..16], &0x40u64.to_le_bytes());
    assert_eq!(&b[16..20], &(-5i32).to_le_bytes());
    assert_eq!(&b[20..24], &42u32.to_le_bytes());
    assert_eq!(&b[24..32], &0x1111u64.to_le_bytes());
    assert_eq!(&b[32..40], &0x2222u64.to_le_bytes());
    assert_eq!(&b[40..48], &0x3333u64.to_le_bytes());
    assert_eq!(&b[48..52], &100u32.to_le_bytes());
    assert_eq!(&b[52..56], &900u32.to_le_bytes());
    assert_eq!(SchedAttr::from_bytes(&b), a);
}

#[test]
fn flag_bits_match_uapi() {
    assert_eq!(FLAG_ALL, 0x7f);
    assert_eq!(FLAG_KEEP_ALL, 0x18);
    assert_eq!(FLAG_UTIL_CLAMP, 0x60);
    assert_eq!(FLAG_SUGOV, 0x1000_0000);
}

// --- uclamp ----------------------------------------------------------------

#[test]
fn uclamp_rejects_above_capacity_scale() {
    let a = SchedAttr { flags: FLAG_UTIL_CLAMP_MIN, util_min: CAPACITY_SCALE + 1, ..Default::default() };
    assert_eq!(uclamp_validate(&a, 0, CAPACITY_SCALE), Err(EINVAL));
    let a = SchedAttr { flags: FLAG_UTIL_CLAMP_MIN, util_min: CAPACITY_SCALE, ..Default::default() };
    assert_eq!(uclamp_validate(&a, 0, CAPACITY_SCALE), Ok(()));
}

#[test]
fn uclamp_reset_sentinel_passes_validation() {
    // int util_min = (u32)-1 => -1; (-1)+1 = 0 which is <= 1025.
    let a = SchedAttr { flags: FLAG_UTIL_CLAMP_MIN, util_min: UCLAMP_RESET, ..Default::default() };
    assert_eq!(uclamp_validate(&a, 0, CAPACITY_SCALE), Ok(()));
}

#[test]
fn uclamp_min_above_max_is_einval() {
    let a = SchedAttr { flags: FLAG_UTIL_CLAMP, util_min: 800, util_max: 700, ..Default::default() };
    assert_eq!(uclamp_validate(&a, 0, CAPACITY_SCALE), Err(EINVAL));
}

#[test]
fn uclamp_min_is_compared_against_the_tasks_live_max() {
    // Only UTIL_CLAMP_MIN is requested, so util_max comes from the task.
    let a = SchedAttr { flags: FLAG_UTIL_CLAMP_MIN, util_min: 900, ..Default::default() };
    assert_eq!(uclamp_validate(&a, 0, 500), Err(EINVAL));
    assert_eq!(uclamp_validate(&a, 0, 1000), Ok(()));
}

#[test]
fn uclamp_request_marks_the_clamp_user_defined() {
    let a = SchedAttr { flags: FLAG_UTIL_CLAMP_MIN, util_min: 300, ..Default::default() };
    let cur = UclampSe { value: 0, user_defined: false };
    assert_eq!(uclamp_apply(&a, true, cur, false), UclampSe { value: 300, user_defined: true });
    // The max clamp is untouched by a MIN-only request once user-defined.
    let cur_max = UclampSe { value: 700, user_defined: true };
    assert_eq!(uclamp_apply(&a, false, cur_max, false), cur_max);
}

#[test]
fn uclamp_sentinel_resets_to_the_class_default() {
    let a = SchedAttr { flags: FLAG_UTIL_CLAMP_MIN, util_min: UCLAMP_RESET, ..Default::default() };
    let cur = UclampSe { value: 300, user_defined: true };
    assert_eq!(uclamp_apply(&a, true, cur, false), UclampSe { value: 0, user_defined: false });
    // RT tasks default to a 100% min boost.
    assert_eq!(uclamp_apply(&a, true, cur, true),
               UclampSe { value: UCLAMP_MIN_RT_DEFAULT, user_defined: false });
}

#[test]
fn a_plain_setscheduler_resets_only_non_user_defined_clamps() {
    let a = SchedAttr::default();
    let user = UclampSe { value: 300, user_defined: true };
    assert_eq!(uclamp_apply(&a, true, user, false), user);
    let auto = UclampSe { value: 300, user_defined: false };
    assert_eq!(uclamp_apply(&a, true, auto, false), UclampSe { value: 0, user_defined: false });
    assert_eq!(uclamp_apply(&a, false, auto, false),
               UclampSe { value: CAPACITY_SCALE, user_defined: false });
}
