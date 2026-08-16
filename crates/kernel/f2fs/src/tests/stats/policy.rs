//! The policy set and the condition list.

use crate::stats::policy::{self, ipu};

/// An empty set reads as disabled, not as a set with no names in it: the two
/// would look identical on the line and mean different things.
#[test]
fn an_empty_policy_set_reads_as_disabled() {
    assert!(policy::ipu_disabled(0));
    assert_eq!(policy::ipu_text(0), " DISABLE");
}

/// Every armed policy is named, in bit order, so a reader splits on spaces.
#[test]
fn every_armed_policy_is_named_in_bit_order() {
    let set = (1 << ipu::FORCE) | (1 << ipu::FSYNC) | (1 << ipu::HONOR_OPU_WRITE);
    assert_eq!(policy::ipu_text(set), " FORCE FSYNC HONOR_OPU_WRITE");
}

/// This build takes a fresh block for every write, so reporting any policy
/// would say in-place update is armed where it can never happen.
#[test]
fn this_build_arms_no_in_place_update_policy() {
    assert_eq!(policy::ipu_policy(&crate::opts::Options::defaults()), 0);
}

/// A mount in no reportable condition prints no list at all — an empty
/// bracket would say the list was consulted and is a different claim.
#[test]
fn a_mount_in_no_reportable_condition_prints_nothing() {
    assert_eq!(policy::sbi_flag_text(0), "");
}

/// Conditions are listed by the name of the bit, in bit order.
#[test]
fn the_conditions_are_listed_by_name_in_bit_order() {
    let word = (1u64 << 15) | (1u64 << 0) | (1u64 << 2);
    assert_eq!(policy::sbi_flag_text(word), "[SBI: fs_dirty need_fsck writable]\n");
}

/// The names sit at the positions the mount's own status attribute publishes,
/// so the two surfaces cannot drift apart.
#[test]
fn the_named_positions_are_the_ones_the_status_attribute_sets() {
    use crate::flags::CP_FSCK_FLAG;
    let dirty = crate::sysfs::status_word(true, false, false, false, 0);
    assert_eq!(policy::sbi_flag_text(dirty), "[SBI: fs_dirty]\n");
    let fsck = crate::sysfs::status_word(false, false, false, false, CP_FSCK_FLAG);
    assert_eq!(policy::sbi_flag_text(fsck), "[SBI: need_fsck]\n");
    let recovering = crate::sysfs::status_word(false, true, false, false, 0);
    assert_eq!(policy::sbi_flag_text(recovering), "[SBI: recovering]\n");
    let disabled = crate::sysfs::status_word(false, false, false, true, 0);
    assert_eq!(policy::sbi_flag_text(disabled), "[SBI: cp_disabled]\n");
    let writable = crate::sysfs::status_word(false, false, true, false, 0);
    assert_eq!(policy::sbi_flag_text(writable), "[SBI: writable]\n");
}
