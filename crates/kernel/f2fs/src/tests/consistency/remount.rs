//! What a running mount may and may not be reconfigured to.

use super::*;
use crate::consistency::{resolve_remount, Sbi};
use crate::opts::BackgroundGc;

fn running(facts: &Facts, line: &str) -> Sbi<'static> {
    let cur = at_mount(facts, line).expect("the mount itself must be legal");
    // Leaked so the borrowed running set outlives this helper. A test process
    // exits; the alternative is threading the owner through every case.
    Sbi { facts: *facts, cur: alloc::boxed::Box::leak(alloc::boxed::Box::new(cur)),
          remount: true, quota_on: false, casefold_loadable: true }
}

#[test]
fn the_cleaner_may_be_turned_off_and_on_again() {
    let sbi = running(&plain(), "");
    let o = resolve_remount(&sbi, "background_gc=off").expect("accepted").0;
    assert_eq!(o.background_gc, BackgroundGc::Off);
    let sbi = Sbi { cur: &o, ..sbi };
    let o = resolve_remount(&sbi, "background_gc=on").expect("accepted").0;
    assert_eq!(o.background_gc, BackgroundGc::On);
}

#[test]
fn an_option_the_new_line_stops_naming_goes_back_to_its_default() {
    let sbi = running(&plain(), "background_gc=off,nolazytime");
    assert_eq!(sbi.cur.background_gc, BackgroundGc::Off);
    assert!(!sbi.cur.lazytime);
    let o = resolve_remount(&sbi, "").expect("accepted").0;
    assert_eq!(o.background_gc, BackgroundGc::On);
    assert!(o.lazytime);
}

// ------------------------------------------------- what may not be switched

#[test]
fn the_age_cleaner_may_not_be_switched() {
    let off = running(&plain(), "");
    assert_eq!(resolve_remount(&off, "atgc"), Err(Errno::Einval));
    let on = running(&plain(), "atgc");
    assert!(on.cur.atgc);
    // No default resets it, so dropping the word from the line leaves the
    // cleaner where it is rather than switching it off — which is the only
    // reason a remount of an atgc mount is legal at all.
    assert!(resolve_remount(&on, "").expect("accepted").0.atgc);
    assert!(resolve_remount(&on, "atgc").is_ok(), "restating it is not a switch");
}

#[test]
fn the_read_extent_cache_may_not_be_switched() {
    let on = running(&plain(), "");
    assert!(on.cur.extent_cache);
    assert_eq!(resolve_remount(&on, "noextent_cache"), Err(Errno::Einval));
    assert!(resolve_remount(&on, "extent_cache").is_ok());
    let off = running(&plain(), "noextent_cache");
    assert_eq!(resolve_remount(&off, "extent_cache"), Err(Errno::Einval));
    assert!(resolve_remount(&off, "noextent_cache").is_ok());
}

#[test]
fn the_age_extent_cache_may_not_be_switched() {
    let off = running(&plain(), "");
    assert_eq!(resolve_remount(&off, "age_extent_cache"), Err(Errno::Einval));
    let on = running(&plain(), "age_extent_cache");
    assert!(resolve_remount(&on, "").expect("accepted").0.age_extent_cache,
            "no default resets it, so dropping the word is not a switch");
}

#[test]
fn the_discard_unit_may_not_be_switched() {
    let sbi = running(&plain(), "");
    assert_eq!(resolve_remount(&sbi, "discard_unit=segment"), Err(Errno::Einval));
    assert!(resolve_remount(&sbi, "discard_unit=block").is_ok());
}

#[test]
fn the_free_node_bitmap_may_not_be_switched() {
    let off = running(&plain(), "");
    assert!(!off.cur.nat_bits);
    assert_eq!(resolve_remount(&off, "nat_bits"), Err(Errno::Einval));
    let on = running(&plain(), "nat_bits");
    assert!(on.cur.nat_bits);
    assert!(resolve_remount(&on, "").expect("accepted").0.nat_bits,
            "no default resets it, so dropping the word is not a switch");
    assert!(resolve_remount(&on, "nat_bits").is_ok());
}

#[test]
fn a_read_only_remount_may_not_also_turn_the_checkpoint_off() {
    let sbi = running(&plain(), "");
    assert!(resolve_remount(&sbi, "checkpoint=disable").is_ok());
    let ro = Sbi { facts: Facts { mount_ro: true, ..plain() }, ..sbi };
    assert_eq!(resolve_remount(&ro, "checkpoint=disable"), Err(Errno::Einval));
}

// --------------------------------------------------------------- reserves

#[test]
fn a_reserve_the_mount_already_holds_is_kept_rather_than_changed() {
    let sbi = running(&plain(), "reserve_root=128,reserve_node=64");
    let (o, spec) = resolve_remount(&sbi, "reserve_root=999,reserve_node=999")
        .expect("accepted");
    assert_eq!(o.reserve_root, 128, "the running reserve is preserved");
    assert_eq!(o.reserve_node, 64);
    assert!(!spec.reserve_root && !spec.reserve_node);
}

#[test]
fn a_mount_with_no_reserve_takes_the_one_the_remount_names() {
    let sbi = running(&plain(), "");
    let o = resolve_remount(&sbi, "reserve_root=128").expect("accepted").0;
    assert_eq!(o.reserve_root, 128);
}


