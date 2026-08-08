// Per-syscall argument ladders: mbind(2), set_mempolicy_home_node(2),
// move_pages(2).

use crate::mempolicy::args::*;
use crate::mempolicy::uapi::*;
use crate::Error;

const PAGE: u64 = 0x1000;
const BASE: u64 = 0x4000_0000;

#[test]
fn mbind_rejects_undefined_flags_before_checking_the_capability() {
    // MPOL_MF_LAZY is defined in the UAPI header but is NOT in MPOL_MF_VALID.
    assert_eq!(mbind_flags(MPOL_MF_LAZY, true), Err(Error::Inval));
    assert_eq!(mbind_flags(1 << 20, true), Err(Error::Inval));
    // An undefined bit alongside MOVE_ALL is EINVAL, not EPERM — the flag
    // mask test comes first.
    assert_eq!(mbind_flags(MPOL_MF_LAZY | MPOL_MF_MOVE_ALL, false), Err(Error::Inval));
}

#[test]
fn mbind_move_all_needs_cap_sys_nice() {
    assert_eq!(mbind_flags(MPOL_MF_MOVE_ALL, false), Err(Error::Perm));
    assert_eq!(mbind_flags(MPOL_MF_MOVE_ALL, true), Ok(()));
    // MPOL_MF_MOVE (without _ALL) is unprivileged.
    assert_eq!(mbind_flags(MPOL_MF_MOVE, false), Ok(()));
    assert_eq!(mbind_flags(MPOL_MF_STRICT | MPOL_MF_MOVE, false), Ok(()));
}

#[test]
fn move_pages_rejects_strict_which_mbind_accepts() {
    assert_eq!(move_pages_flags(MPOL_MF_STRICT, true), Err(Error::Inval));
    assert_eq!(mbind_flags(MPOL_MF_STRICT, true), Ok(()));
    assert_eq!(move_pages_flags(MPOL_MF_MOVE, false), Ok(()));
    assert_eq!(move_pages_flags(MPOL_MF_MOVE_ALL, false), Err(Error::Perm));
    assert_eq!(move_pages_flags(MPOL_MF_MOVE_ALL, true), Ok(()));
}

#[test]
fn an_unaligned_start_is_einval() {
    assert_eq!(align_range(BASE + 1, PAGE), Err(Error::Inval));
    assert_eq!(align_range(BASE, PAGE), Ok(Some((BASE, BASE + PAGE))));
}

#[test]
fn len_is_rounded_up_and_zero_length_is_a_successful_no_op() {
    assert_eq!(align_range(BASE, 1), Ok(Some((BASE, BASE + PAGE))));
    assert_eq!(align_range(BASE, PAGE + 1), Ok(Some((BASE, BASE + 2 * PAGE))));
    assert_eq!(align_range(BASE, 0), Ok(None));
}

#[test]
fn a_length_that_rounds_up_to_zero_is_a_no_op_here_unlike_mseal() {
    // mbind has no separate "len rounds to zero but was nonzero" guard, so
    // the page-align wrap lands on `end == start` and returns 0.
    assert_eq!(align_range(BASE, u64::MAX), Ok(None));
}

#[test]
fn an_end_that_wraps_is_einval() {
    assert_eq!(align_range(0xffff_ffff_ffff_0000, 0x2_0000), Err(Error::Inval));
}

#[test]
fn home_node_minus_one_is_einval_because_the_argument_is_unsigned() {
    // `home_node` is declared `unsigned long`, so -1 arrives as ULONG_MAX and
    // trips `home_node >= MAX_NUMNODES`. The old shim accepted -1 and
    // REJECTED 0 — exactly backwards.
    assert!(!home_node_ok(u64::MAX));
    assert!(!home_node_ok((-1i64) as u64));
    assert!(home_node_ok(0));
    assert!(!home_node_ok(1), "node 1 has no memory on a single-node PMM");
    assert!(!home_node_ok(MAX_NUMNODES));
}

#[test]
fn move_pages_target_node_ladder() {
    assert_eq!(move_pages_target_node(0), Ok(NODE_ID_LOCAL));
    assert_eq!(move_pages_target_node(-1), Err(MovePagesNodeErr::NoDev));
    assert_eq!(move_pages_target_node(MAX_NUMNODES as i32), Err(MovePagesNodeErr::NoDev));
    assert_eq!(move_pages_target_node(1), Err(MovePagesNodeErr::NoDev),
               "in range but memoryless ⇒ ENODEV");
}

#[test]
fn page_align_matches_the_kernel_macro() {
    assert_eq!(page_align(0), 0);
    assert_eq!(page_align(1), PAGE);
    assert_eq!(page_align(PAGE), PAGE);
    assert_eq!(page_align(PAGE + 1), 2 * PAGE);
    assert_eq!(page_align(u64::MAX), 0, "wraps, exactly as PAGE_ALIGN does");
}
