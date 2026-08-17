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

/// The report names the set the WRITER consults, position for position: a
/// reader decodes the line by bit number, so a name that moved would rename
/// somebody else's policy.
#[test]
fn the_reported_names_sit_at_the_positions_the_writer_reads() {
    assert_eq!(policy::IPU_NAMES.len(), ipu::MAX as usize);
    assert_eq!(policy::IPU_NAMES[ipu::FORCE as usize], "FORCE");
    assert_eq!(policy::IPU_NAMES[ipu::SSR as usize], "SSR");
    assert_eq!(policy::IPU_NAMES[ipu::HONOR_OPU_WRITE as usize], "HONOR_OPU_WRITE");
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
    use crate::sbflags::{bits, Derived, SbFlags};
    let none = Derived::default();
    let word = |d: Derived| SbFlags::new().word(d);
    assert_eq!(policy::sbi_flag_text(word(Derived { dirty: true, ..none })),
               "[SBI: fs_dirty]\n");
    assert_eq!(policy::sbi_flag_text(word(Derived { recovering: true, ..none })),
               "[SBI: recovering]\n");
    assert_eq!(policy::sbi_flag_text(word(Derived { quota_dirty: true, ..none })),
               "[SBI: quota_need_flush]\n");
    assert_eq!(policy::sbi_flag_text(
                   SbFlags::at_mount(crate::flags::CP_FSCK_FLAG).word(none)),
               "[SBI: need_fsck]\n");
    let mut f = SbFlags::new();
    f.disable_checkpoint(false);
    assert_eq!(policy::sbi_flag_text(f.word(none)), "[SBI: cp_disabled]\n");
    let mut g = SbFlags::new();
    g.recovered();
    assert_eq!(policy::sbi_flag_text(g.word(none)), "[SBI: recovered]\n");
    let mut h = SbFlags::new();
    h.set_closing(true);
    assert_eq!(policy::sbi_flag_text(h.word(none)), "[SBI: closing]\n");
    // Every name the report knows sits at a position `bits` names, and every
    // position it names has a name.
    for (pos, _) in policy::SBI_FLAG_NAMES { assert!(pos < bits::MAX_SBI_FLAG); }
    assert_eq!(policy::SBI_FLAG_NAMES.len(), bits::MAX_SBI_FLAG as usize);
}
