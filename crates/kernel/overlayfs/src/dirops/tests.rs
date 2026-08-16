//! Create, remove and rename end to end, against real layers.
//!
//! Each case checks the merged view the caller sees AND what the writable
//! layer actually holds — a delete that leaves no cover looks right until the
//! next lookup, and a cover left where nothing is below looks right until the
//! parent cannot be removed.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::types::{FileType, S_IFCHR, S_IFREG};
use vfs::InodeRef;

use crate::config::{Config, RedirectMode};
use crate::layers::{LayerStack, OvlEntry};
use crate::lookup::lookup;
use crate::readdir::{merged, visible};
use crate::testfs::{layer, lookup as find_path, mkfile, mkpath, mkwhiteout, names, slurp, stack};
use crate::whiteout;

use super::create::{create, creating_whiteout_refused, New};
use super::remove::{lower_positive, remove_name};
use super::rename::rename;

/// A two-layer mount, with the writable layer's root already present.
fn mount(config: Config) -> (Arc<LayerStack>, OvlEntry, InodeRef, InodeRef) {
    let up = layer(0);
    let lo = layer(1);
    let (s, root) = stack(config, Some(up.clone()), &[lo.clone()], &[]);
    (s, root, up, lo)
}

/// The names the merged root shows.
fn root_names(s: &Arc<LayerStack>, root: &OvlEntry) -> alloc::vec::Vec<alloc::string::String> {
    let mut v: alloc::vec::Vec<_> =
        visible(&merged(s, root).unwrap()).map(|e| e.name.clone()).collect();
    v.retain(|n| n != "..work");
    v.sort();
    v
}

// ---- create ------------------------------------------------------------

#[test]
fn a_new_file_lands_in_the_writable_layer() {
    let (s, root, up, _lo) = mount(Config::default());
    create(&s, &root, "f", New::File(S_IFREG as u32 | 0o644), false).unwrap();
    assert!(find_path(&up, "f").is_some());
}

#[test]
fn creating_over_an_existing_name_is_refused() {
    let (s, root, up, _lo) = mount(Config::default());
    mkfile(&up, "f", b"x");
    assert_eq!(create(&s, &root, "f", New::File(S_IFREG as u32 | 0o644), false).err(),
               Some(Errno::Eexist));
}

#[test]
fn creating_over_a_cover_replaces_it() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"below");
    mkwhiteout(&up, "f");
    create(&s, &root, "f", New::File(S_IFREG as u32 | 0o644), false).unwrap();
    let now = find_path(&up, "f").unwrap();
    assert!(!whiteout::is_device(&now));
    assert_eq!(now.file_type(), FileType::Regular);
    // The lower file must not come back through the new name.
    let e = lookup(&s, &root, &root, "f").unwrap().unwrap();
    assert!(e.lower.is_empty());
}

#[test]
fn a_new_directory_over_a_cover_hides_the_lower_one() {
    let c = Config::default();
    let (s, root, up, lo) = mount(c.clone());
    mkfile(&lo, "d/was-here", b"x");
    mkwhiteout(&up, "d");
    create(&s, &root, "d", New::Dir(0o755), false).unwrap();
    let made = find_path(&up, "d").unwrap();
    assert!(whiteout::is_opaque(&c, &made),
            "without this the deleted directory's contents reappear");
    let e = lookup(&s, &root, &root, "d").unwrap().unwrap();
    assert!(visible(&merged(&s, &e).unwrap()).next().is_none());
}

#[test]
fn the_work_directory_is_left_empty_after_creating_over_a_cover() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"below");
    mkwhiteout(&up, "f");
    create(&s, &root, "f", New::File(S_IFREG as u32 | 0o644), false).unwrap();
    assert!(names(&find_path(&up, "..work").unwrap()).is_empty());
}

#[test]
fn making_a_cover_by_hand_is_refused() {
    // It would make an arbitrary lower file disappear, which is not something
    // `mknod` may do.
    assert!(creating_whiteout_refused(S_IFCHR as u32, 0));
    assert!(!creating_whiteout_refused(S_IFCHR as u32, 0x0501));
    assert!(!creating_whiteout_refused(S_IFREG as u32, 0));
}

#[test]
fn a_symlink_and_a_device_can_be_created() {
    let (s, root, up, _lo) = mount(Config::default());
    create(&s, &root, "l", New::Symlink(b"/t".to_vec()), false).unwrap();
    create(&s, &root, "dev", New::Node(S_IFCHR as u32 | 0o600, 0x0501), false).unwrap();
    assert_eq!(find_path(&up, "l").unwrap().file_type(), FileType::Symlink);
    assert_eq!(find_path(&up, "dev").unwrap().rdev(), 0x0501);
}

// ---- remove ------------------------------------------------------------

#[test]
fn removing_a_file_that_exists_only_above_leaves_nothing_behind() {
    // A cover here would cost an object in the writable layer and stop the
    // parent from ever being removed.
    let (s, root, up, _lo) = mount(Config::default());
    mkfile(&up, "f", b"x");
    remove_name(&s, &root, &root, "f", false).unwrap();
    assert!(find_path(&up, "f").is_none());
    assert!(lookup(&s, &root, &root, "f").unwrap().is_none());
}

#[test]
fn removing_a_file_that_exists_below_leaves_a_cover() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"below");
    remove_name(&s, &root, &root, "f", false).unwrap();
    let cover = find_path(&up, "f").expect("a cover must be left");
    assert!(whiteout::is_device(&cover));
    assert!(lookup(&s, &root, &root, "f").unwrap().is_none(), "the lower file must stay hidden");
    assert_eq!(slurp(&find_path(&lo, "f").unwrap()), b"below".to_vec(), "and stay intact");
}

#[test]
fn removing_a_copied_up_file_still_leaves_a_cover() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"below");
    mkfile(&up, "f", b"above");
    remove_name(&s, &root, &root, "f", false).unwrap();
    assert!(whiteout::is_device(&find_path(&up, "f").unwrap()));
    assert!(lookup(&s, &root, &root, "f").unwrap().is_none());
}

#[test]
fn the_work_directory_is_left_empty_after_a_removal() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"below");
    mkfile(&up, "f", b"above");
    remove_name(&s, &root, &root, "f", false).unwrap();
    assert!(names(&find_path(&up, "..work").unwrap()).is_empty());
}

#[test]
fn a_non_empty_directory_is_refused() {
    let (s, root, _up, lo) = mount(Config::default());
    mkfile(&lo, "d/inside", b"x");
    assert_eq!(remove_name(&s, &root, &root, "d", true).err(), Some(Errno::Enotempty));
}

#[test]
fn a_directory_whose_contents_were_all_deleted_can_be_removed() {
    // `rm -r` of an image directory: every entry is covered, and the directory
    // itself then has to go.
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "d/a", b"x");
    let ud = mkpath(&up, "d");
    mkwhiteout(&ud, "a");
    remove_name(&s, &root, &root, "d", true).unwrap();
    assert!(whiteout::is_device(&find_path(&up, "d").unwrap()));
    assert!(lookup(&s, &root, &root, "d").unwrap().is_none());
}

#[test]
fn removing_a_directory_of_the_wrong_type_is_refused() {
    let (s, root, _up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"x");
    mkpath(&lo, "d");
    assert_eq!(remove_name(&s, &root, &root, "f", true).err(), Some(Errno::Enotdir));
    assert_eq!(remove_name(&s, &root, &root, "d", false).err(), Some(Errno::Eisdir));
}

#[test]
fn removing_a_name_that_is_not_there_is_enoent() {
    let (s, root, _up, _lo) = mount(Config::default());
    assert_eq!(remove_name(&s, &root, &root, "absent", false).err(), Some(Errno::Enoent));
}

#[test]
fn whether_something_is_below_is_decided_by_looking() {
    let (s, root, _up, lo) = mount(Config::default());
    mkfile(&lo, "here", b"x");
    assert!(lower_positive(&s, &root, "here"));
    assert!(!lower_positive(&s, &root, "absent"));
    mkwhiteout(&lo, "covered");
    assert!(!lower_positive(&s, &root, "covered"), "a cover below is not something below");
}

// ---- rename ------------------------------------------------------------

#[test]
fn renaming_a_file_inside_the_writable_layer() {
    let (s, root, up, _lo) = mount(Config::default());
    mkfile(&up, "a", b"x");
    let e = lookup(&s, &root, &root, "a").unwrap().unwrap();
    rename(&s, &root, "a", &e, &root, "b", None, 0, &["a"]).unwrap();
    assert!(find_path(&up, "a").is_none());
    assert_eq!(slurp(&find_path(&up, "b").unwrap()), b"x".to_vec());
}

#[test]
fn renaming_away_from_a_name_that_exists_below_leaves_a_cover() {
    // Otherwise the lower file reappears under the name that was just vacated.
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "a", b"below");
    mkfile(&up, "a", b"above");
    let e = lookup(&s, &root, &root, "a").unwrap().unwrap();
    rename(&s, &root, "a", &e, &root, "b", None, 0, &["a"]).unwrap();
    assert!(whiteout::is_device(&find_path(&up, "a").unwrap()));
    assert!(lookup(&s, &root, &root, "a").unwrap().is_none());
    assert_eq!(slurp(&find_path(&up, "b").unwrap()), b"above".to_vec());
}

#[test]
fn renaming_onto_a_cover_replaces_it_and_leaves_one_behind() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "a", b"below-a");
    mkfile(&lo, "b", b"below-b");
    mkfile(&up, "a", b"above-a");
    mkwhiteout(&up, "b");
    let e = lookup(&s, &root, &root, "a").unwrap().unwrap();
    rename(&s, &root, "a", &e, &root, "b", None, 0, &["a"]).unwrap();
    assert_eq!(slurp(&find_path(&up, "b").unwrap()), b"above-a".to_vec());
    assert!(whiteout::is_device(&find_path(&up, "a").unwrap()));
    assert!(lookup(&s, &root, &root, "a").unwrap().is_none());
}

#[test]
fn a_merged_directory_cannot_be_renamed_without_the_record() {
    let (s, root, up, lo) = mount(Config::default());
    mkpath(&lo, "d");
    mkpath(&up, "d");
    let e = lookup(&s, &root, &root, "d").unwrap().unwrap();
    assert_eq!(rename(&s, &root, "d", &e, &root, "e", None, 0, &["d"]).err(), Some(Errno::Exdev));
}

#[test]
fn with_the_record_on_a_merged_directory_moves_and_keeps_its_lower_half() {
    let c = Config { redirect_mode: RedirectMode::On, ..Config::default() };
    let (s, root, up, lo) = mount(c.clone());
    mkfile(&lo, "d/below", b"x");
    mkpath(&up, "d");
    let e = lookup(&s, &root, &root, "d").unwrap().unwrap();
    rename(&s, &root, "d", &e, &root, "moved", None, 0, &["d"]).unwrap();
    let moved = lookup(&s, &root, &root, "moved").unwrap().unwrap();
    assert_eq!(moved.lower.len(), 1, "the lower half must still be found");
    let names: alloc::vec::Vec<_> =
        visible(&merged(&s, &moved).unwrap()).map(|x| x.name.clone()).collect();
    assert_eq!(names, vec!["below"]);
}

#[test]
fn a_directory_only_in_the_writable_layer_renames_without_the_record() {
    let (s, root, up, _lo) = mount(Config::default());
    mkpath(&up, "d");
    let e = lookup(&s, &root, &root, "d").unwrap().unwrap();
    rename(&s, &root, "d", &e, &root, "e", None, 0, &["d"]).unwrap();
    assert!(find_path(&up, "e").is_some());
}

#[test]
fn an_unsupported_rename_flag_is_refused() {
    let (s, root, up, _lo) = mount(Config::default());
    mkfile(&up, "a", b"x");
    let e = lookup(&s, &root, &root, "a").unwrap().unwrap();
    assert_eq!(rename(&s, &root, "a", &e, &root, "b", None, 1 << 5, &["a"]).err(),
               Some(Errno::Einval));
}

#[test]
fn refusing_to_replace_is_honoured() {
    let (s, root, up, _lo) = mount(Config::default());
    mkfile(&up, "a", b"x");
    mkfile(&up, "b", b"y");
    let a = lookup(&s, &root, &root, "a").unwrap().unwrap();
    let b = lookup(&s, &root, &root, "b").unwrap().unwrap();
    assert_eq!(rename(&s, &root, "a", &a, &root, "b", Some(&b),
                      super::plan::RENAME_NOREPLACE, &["a"]).err(), Some(Errno::Eexist));
}

#[test]
fn the_merged_view_is_consistent_after_a_delete_and_a_recreate() {
    let (s, root, _up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"below");
    assert_eq!(root_names(&s, &root), vec!["f"]);
    remove_name(&s, &root, &root, "f", false).unwrap();
    assert!(root_names(&s, &root).is_empty());
    create(&s, &root, "f", New::File(S_IFREG as u32 | 0o644), false).unwrap();
    assert_eq!(root_names(&s, &root), vec!["f"]);
    let e = lookup(&s, &root, &root, "f").unwrap().unwrap();
    assert_eq!(slurp(&e.real().unwrap()), Vec::<u8>::new(), "the new file is not the old one");
}
