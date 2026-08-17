//! Each clause a fresh mount can trip, broken one at a time.

use super::*;
use crate::flags::{FEATURE_BLKZONED, FEATURE_CASEFOLD, FEATURE_DEVICE_ALIAS, FEATURE_ENCRYPT,
                   FEATURE_EXTRA_ATTR, FEATURE_FLEXIBLE_INLINE_XATTR, FEATURE_RO};
use crate::opts::{DiscardUnit, Mode};

// ------------------------------------------------------------- the replay

#[test]
fn norecovery_needs_a_read_only_mount() {
    assert_eq!(at_mount(&plain(), "norecovery"), Err(Errno::Einval));
    let ro = Facts { mount_ro: true, ..plain() };
    assert!(at_mount(&ro, "norecovery").is_ok());
}

#[test]
fn the_other_spelling_does_not_need_one() {
    // `disable_roll_forward` stops the replay without claiming the mount is
    // read-only, so it is legal on a writable mount and `norecovery` is not.
    let o = at_mount(&plain(), "disable_roll_forward").expect("accepted");
    assert!(!o.recovery);
    assert!(!o.norecovery);
}

// -------------------------------------------------------------- discard

#[test]
fn a_zoned_volume_refuses_nodiscard() {
    let z = Facts { feature: FEATURE_BLKZONED, ..plain() };
    assert_eq!(at_mount(&z, "nodiscard"), Err(Errno::Einval));
}

#[test]
fn a_zoned_volume_that_was_not_asked_keeps_its_discard() {
    let z = Facts { feature: FEATURE_BLKZONED, ..plain() };
    assert!(at_mount(&z, "").expect("accepted").discard);
}

#[test]
fn a_device_that_cannot_discard_drops_the_request_rather_than_refusing() {
    let (o, spec) = at_mount_spec(&plain(), "discard").expect("accepted");
    assert!(!o.discard, "the request is dropped");
    assert!(!spec.discard, "and stops being a request");
}

#[test]
fn a_device_that_can_discard_keeps_it() {
    let can = Facts { hw_support_discard: true, ..plain() };
    assert!(at_mount(&can, "discard").expect("accepted").discard);
}

// --------------------------------------------------------- extent cache

#[test]
fn an_aliased_device_refuses_noextent_cache() {
    let a = Facts { feature: FEATURE_DEVICE_ALIAS, ..plain() };
    assert_eq!(at_mount(&a, "noextent_cache"), Err(Errno::Einval));
    assert!(at_mount(&a, "").is_ok());
    assert!(at_mount(&plain(), "noextent_cache").is_ok());
}

// -------------------------------------------------------------- casefold

#[test]
fn a_folding_volume_whose_table_will_not_load_is_refused() {
    let c = Facts { feature: FEATURE_CASEFOLD, ..plain() };
    let base = Options::defaults_for(&c);
    let mut sbi = crate::consistency::Sbi::at_mount(c, &base);
    sbi.casefold_loadable = false;
    let (mut o, mut spec) = (sbi.cur.clone(), Spec::none());
    assert_eq!(crate::consistency::check_opt_consistency(&sbi, &mut o, &mut spec),
               Err(Errno::Einval));
    sbi.casefold_loadable = true;
    assert!(crate::consistency::check_opt_consistency(&sbi, &mut o, &mut spec).is_ok());
}

// ----------------------------------------------------------------- zoned

#[test]
fn a_zoned_volume_needs_the_cleaner() {
    let z = Facts { feature: FEATURE_BLKZONED, ..plain() };
    assert_eq!(at_mount(&z, "background_gc=off"), Err(Errno::Einval));
    assert!(at_mount(&z, "background_gc=sync").is_ok());
    assert!(at_mount(&plain(), "background_gc=off").is_ok());
}

#[test]
fn a_zoned_volume_widens_a_narrow_discard_unit_rather_than_refusing() {
    let z = Facts { feature: FEATURE_BLKZONED, ..plain() };
    let o = at_mount(&z, "discard_unit=block").expect("accepted");
    assert_eq!(o.discard_unit, DiscardUnit::Section);
    let o = at_mount(&z, "discard_unit=segment").expect("accepted");
    assert_eq!(o.discard_unit, DiscardUnit::Section);
}

/// A mount that names NOTHING gets the same answer. This is the reference's
/// zoned DEFAULT, set before an option is read, and it is not a tuning choice:
/// a section is a zone, and a zone's blocks come back only when the drive is
/// asked to reset the whole of it. Announcing a block or a segment leaves the
/// write pointer where it was, so the space returns in the accounting and
/// never on the drive — the volume fills and stays full.
///
/// Asserted over an EMPTY spec, which is what the mount path passes: nothing
/// there knows what a line named, and the clause used to be conditional on a
/// line having named the option. Going through `resolve` instead would prove
/// nothing — its feature-derived defaults already answer `Section`, and that
/// path has no production caller.
#[test]
fn a_zoned_volume_that_names_no_discard_unit_still_gets_sections() {
    let z = Facts { feature: FEATURE_BLKZONED, ..plain() };
    let mut o = crate::opts::Options::defaults();
    assert_eq!(o.discard_unit, DiscardUnit::Block, "the build-wide default is not the block");
    let mut spec = Spec::default();
    let cur = o.clone();
    let sbi = crate::consistency::Sbi::at_mount(z, &cur);
    crate::consistency::check_opt_consistency(&sbi, &mut o, &mut spec).expect("accepted");
    assert_eq!(o.discard_unit, DiscardUnit::Section);
    // And a volume with no zones is left alone: its default is the block.
    let mut o = crate::opts::Options::defaults();
    let cur = o.clone();
    let sbi = crate::consistency::Sbi::at_mount(plain(), &cur);
    crate::consistency::check_opt_consistency(&sbi, &mut o, &mut Spec::default())
        .expect("accepted");
    assert_eq!(o.discard_unit, DiscardUnit::Block);
}

#[test]
fn a_zoned_volume_refuses_any_mode_but_lfs() {
    let z = Facts { feature: FEATURE_BLKZONED, ..plain() };
    assert_eq!(at_mount(&z, "mode=adaptive"), Err(Errno::Einval));
    assert_eq!(at_mount(&z, "mode=fragment:block"), Err(Errno::Einval));
    assert_eq!(at_mount(&z, "mode=lfs").expect("accepted").mode, Mode::Lfs);
    // Unnamed, the default already is LFS, so nothing is refused.
    assert_eq!(at_mount(&z, "").expect("accepted").mode, Mode::Lfs);
}

// ------------------------------------------------------- inline xattr size

const FLEX: u32 = FEATURE_EXTRA_ATTR | FEATURE_FLEXIBLE_INLINE_XATTR;

#[test]
fn sizing_the_inline_region_needs_both_features() {
    assert_eq!(at_mount(&plain(), "inline_xattr_size=40"), Err(Errno::Einval));
    let one = Facts { feature: FEATURE_EXTRA_ATTR, ..plain() };
    assert_eq!(at_mount(&one, "inline_xattr_size=40"), Err(Errno::Einval));
    let other = Facts { feature: FEATURE_FLEXIBLE_INLINE_XATTR, ..plain() };
    assert_eq!(at_mount(&other, "inline_xattr_size=40"), Err(Errno::Einval));
    let both = Facts { feature: FLEX, ..plain() };
    assert_eq!(at_mount(&both, "inline_xattr_size=40").expect("accepted").inline_xattr_size,
               Some(40));
}

#[test]
fn sizing_the_inline_region_needs_the_region() {
    // At a FRESH mount the volume's derived defaults already reserve the
    // region, so the line only has to not be the sole thing asking for it —
    // which is why `noinline_xattr` on its own line is still accepted.
    let both = Facts { feature: FLEX, ..plain() };
    assert!(at_mount(&both, "noinline_xattr,inline_xattr_size=40").is_ok());
    // The clause bites where the region is genuinely absent: a mount already
    // running without it, reconfigured to size it.
    let cur = at_mount(&both, "noinline_xattr").expect("legal");
    let sbi = crate::consistency::Sbi { facts: both, cur: &cur, remount: true, quota_on: false,
                                        casefold_loadable: true };
    assert_eq!(crate::consistency::resolve_remount(&sbi, "noinline_xattr,inline_xattr_size=40")
                   .map(|(o, _)| o.inline_xattr_size),
               Err(Errno::Einval));
    assert!(crate::consistency::resolve_remount(&sbi, "inline_xattr,inline_xattr_size=40").is_ok());
}

// ------------------------------------------------------------------ atgc

#[test]
fn the_age_cleaner_and_a_never_overwriting_volume_do_not_go_together() {
    assert_eq!(at_mount(&plain(), "atgc,mode=lfs"), Err(Errno::Einval));
    assert_eq!(at_mount(&plain(), "mode=lfs,atgc"), Err(Errno::Einval));
    assert!(at_mount(&plain(), "atgc").is_ok());
    assert!(at_mount(&plain(), "mode=lfs").is_ok());
}

// ------------------------------------------------------------ read-only

#[test]
fn nothing_may_be_merged_when_nothing_may_be_written() {
    let ro = Facts { mount_ro: true, ..plain() };
    assert_eq!(at_mount(&ro, "flush_merge"), Err(Errno::Einval));
    // The default is derived off on such a mount, so a line naming nothing is
    // not refused by its own default.
    assert!(at_mount(&ro, "").is_ok());
    assert!(at_mount(&plain(), "flush_merge").is_ok());
}

#[test]
fn a_volume_marked_read_only_may_only_be_mounted_read_only() {
    let ro = Facts { feature: FEATURE_RO, ..plain() };
    assert_eq!(at_mount(&ro, ""), Err(Errno::Erofs));
    assert!(at_mount(&Facts { mount_ro: true, ..ro }, "").is_ok());
}

// ------------------------------------------------------- dummy encryption

/// The clause is checked against a policy built by hand rather than parsed:
/// `test_dummy_encryption` is refused at the PARSER on a build that cannot
/// encrypt, so a line carrying it never reaches the clause here.
fn wants_dummy() -> Options {
    Options { dummy_policy: Some(crate::opts::DummyPolicy {
                  version: crate::opts::crypt::PolicyVersion::V2,
                  contents_mode: crate::opts::crypt::MODE_AES_256_XTS,
                  filenames_mode: crate::opts::crypt::MODE_AES_256_CTS }),
              ..Options::defaults() }
}

#[test]
fn the_test_key_needs_the_encrypt_feature() {
    let mut o = wants_dummy();
    let mut spec = Spec::none();
    let plain_base = Options::defaults_for(&plain());
    let sbi = crate::consistency::Sbi::at_mount(plain(), &plain_base);
    assert_eq!(crate::consistency::check_opt_consistency(&sbi, &mut o, &mut spec),
               Err(Errno::Einval));
    let e = Facts { feature: FEATURE_ENCRYPT, ..plain() };
    let e_base = Options::defaults_for(&e);
    let sbi = crate::consistency::Sbi::at_mount(e, &e_base);
    let mut o = wants_dummy();
    assert!(crate::consistency::check_opt_consistency(&sbi, &mut o, &mut spec).is_ok());
}

#[test]
fn the_test_key_may_be_restated_on_a_remount_and_not_introduced() {
    let e = Facts { feature: FEATURE_ENCRYPT, ..plain() };
    let running = Options::defaults_for(&e);
    let mut spec = Spec::none();
    // Introducing it under a mount that does not have it: refused.
    let sbi = crate::consistency::Sbi { facts: e, cur: &running, remount: true,
                                        quota_on: false, casefold_loadable: true };
    let mut o = wants_dummy();
    assert_eq!(crate::consistency::check_opt_consistency(&sbi, &mut o, &mut spec),
               Err(Errno::Einval));
    // Restating what is already in force: accepted.
    let dummy = wants_dummy();
    let sbi = crate::consistency::Sbi { cur: &dummy, ..sbi };
    let mut o = wants_dummy();
    assert!(crate::consistency::check_opt_consistency(&sbi, &mut o, &mut spec).is_ok());
}

// ------------------------------------------------------------- the order

#[test]
fn the_first_clause_is_the_one_reported() {
    // Zoned, read-only-marked, and asking for several impossible things at
    // once: the replay clause comes first and is what answers.
    let f = Facts { feature: FEATURE_BLKZONED | FEATURE_RO, ..plain() };
    assert_eq!(at_mount(&f, "norecovery,nodiscard,atgc"), Err(Errno::Einval));
    // Dropping it uncovers the discard clause, which is also Einval — so the
    // ordering is shown by which clause a legal-elsewhere line trips.
    let f2 = Facts { feature: FEATURE_RO, mount_ro: true, ..plain() };
    assert_eq!(at_mount(&f2, "flush_merge"), Err(Errno::Einval));
    let f3 = Facts { feature: FEATURE_RO, ..plain() };
    assert_eq!(at_mount(&f3, ""), Err(Errno::Erofs), "the last clause is reached");
}
