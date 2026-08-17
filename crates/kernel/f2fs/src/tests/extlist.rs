//! A change to the volume's extension lists, against a real volume.
//!
//! The property under test is PERSISTENCE. A change that only touched memory
//! would pass any assertion made through the same mount, so every case here
//! remounts the bytes the volume left behind and reads the lists off the medium.

use super::*;
use crate::test_image;
use sectors::MemImage;
use syscall::errno::Errno;

fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

/// Both lists as the volume's own superblock holds them.
fn lists(v: &Volume<MemImage>) -> (alloc::vec::Vec<alloc::string::String>,
                                   alloc::vec::Vec<alloc::string::String>) {
    let sb = v.super_block();
    let cold = sb.extension_count as usize;
    let hot = sb.hot_ext_count as usize;
    (sb.extensions.iter().take(cold).cloned().collect(),
     sb.extensions.iter().skip(cold).take(hot).cloned().collect())
}

fn remounted(v: Volume<MemImage>) -> Volume<MemImage> {
    Volume::mount_with(MemImage::from_bytes(crate::uapi::BLKSIZE as u32,
                                           v.into_source().snapshot()),
                       crate::opts::Options::defaults(), true).expect("remount")
}

#[test]
fn a_cold_name_added_is_on_the_medium_for_the_next_mount() {
    let mut v = vol();
    let (cold0, hot0) = lists(&v);
    assert!(!cold0.contains(&alloc::string::String::from("qcow2")));
    v.update_extension_list("qcow2", false, true).expect("add");
    let again = remounted(v);
    let (cold, hot) = lists(&again);
    assert!(cold.contains(&alloc::string::String::from("qcow2")),
            "the change never reached the medium: {cold:?}");
    assert_eq!(cold.len(), cold0.len() + 1);
    assert_eq!(hot, hot0, "adding a cold name moved the hot list");
}

/// The hot entries sit directly after the cold ones in one array, so a cold
/// insertion has to move every hot entry — the case a build that appends gets
/// wrong without any count disagreeing.
#[test]
fn a_cold_insertion_keeps_the_hot_names_in_the_hot_list() {
    let mut v = vol();
    v.update_extension_list("db", true, true).expect("hot");
    v.update_extension_list("log", true, true).expect("hot");
    v.update_extension_list("qcow2", false, true).expect("cold");
    let again = remounted(v);
    let (cold, hot) = lists(&again);
    assert!(hot.contains(&alloc::string::String::from("db")), "{hot:?}");
    assert!(hot.contains(&alloc::string::String::from("log")), "{hot:?}");
    assert!(cold.contains(&alloc::string::String::from("qcow2")), "{cold:?}");
    assert!(!cold.contains(&alloc::string::String::from("db")), "{cold:?}");
}

#[test]
fn a_name_taken_away_is_gone_for_the_next_mount() {
    let mut v = vol();
    let (cold0, _) = lists(&v);
    let victim = cold0.first().cloned().expect("the fixture has a cold list");
    v.update_extension_list(&victim, false, false).expect("remove");
    let again = remounted(v);
    let (cold, _) = lists(&again);
    assert!(!cold.contains(&victim), "the removal never reached the medium: {cold:?}");
    assert_eq!(cold.len(), cold0.len() - 1);
}

/// Every refusal is taken before anything reaches the medium.
#[test]
fn a_refused_change_leaves_the_lists_alone() {
    let mut v = vol();
    let before = lists(&v);
    let held = before.0.first().cloned().expect("the fixture has a cold list");
    // A name already in a list, and a name in neither being taken away.
    assert_eq!(v.update_extension_list(&held, false, true), Err(Errno::Einval));
    assert_eq!(v.update_extension_list("nosuchext", false, false), Err(Errno::Einval));
    assert_eq!(lists(&v), before);
    let again = remounted(v);
    assert_eq!(lists(&again), before);
}

/// A read-only mount may not change the volume's own lists.
#[test]
fn a_read_only_mount_refuses_the_change() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.update_extension_list("qcow2", false, true), Err(Errno::Erofs));
}
