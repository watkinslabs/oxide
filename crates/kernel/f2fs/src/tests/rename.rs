//! Moving names, in all three forms, proved by REMOUNTING.
//!
//! The exchange tests all check BOTH sides. A swap test that looks at one
//! entry passes whether or not anything swapped: the source name still exists
//! either way, and it is the crossing over that the operation promises.

use super::*;
use crate::flags::{FADVISE_LOST_PINO_BIT, FT_CHRDEV, FT_DIR, FT_REG_FILE};
use crate::mode::{S_IFCHR, S_IFDIR, S_IFREG};
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Rename, Volume};
use sectors::MemImage;
use syscall::errno::Errno;
use vfs::namei::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};

const NOW: (u64, u32) = (1_800_000_000, 500);
const OWNER: (u32, u32) = (1000, 1000);

fn spec(mode: u16) -> NewInode {
    NewInode { mode, uid: 1000, gid: 1000, rdev: 0, now: NOW }
}

fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

fn remount(v: Volume<MemImage>) -> Volume<MemImage> {
    let mut v = v;
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// One request, built where the test can read it. # C: O(1)
fn req<'a>(from: u32, old: &'a [u8], to: u32, new: &'a [u8], flags: u32) -> Rename<'a> {
    Rename { from, old, to, new, flags, owner: OWNER, now: NOW }
}

/// A move, with what it replaced discarded — these tests read the medium for
/// that, not the report. # C: O(depth)
fn mv(v: &mut Volume<MemImage>, from: u32, old: &[u8], to: u32, new: &[u8], flags: u32)
    -> Result<(), Errno> {
    v.rename(&req(from, old, to, new, flags)).map(|_| ())
}

/// Look a name up in `dir`. # C: O(depth)
fn look(v: &Volume<MemImage>, dir: u32, name: &[u8]) -> Result<crate::DirEntry, Errno> {
    let d = v.read_inode(dir)?;
    v.lookup(&d, dir, name)
}

fn find(v: &Volume<MemImage>, name: &[u8]) -> Result<crate::DirEntry, Errno> {
    look(v, ROOT_INO, name)
}

// ----------------------------------------------------------------- plain move

#[test]
fn a_renamed_file_answers_to_its_new_name_only() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"old", &spec(S_IFREG | 0o644), None).unwrap();
    mv(&mut v, ROOT_INO, b"old", ROOT_INO, b"new", 0).unwrap();
    let v = remount(v);
    assert_eq!(find(&v, b"old").err(), Some(Errno::Enoent));
    assert_eq!(find(&v, b"new").unwrap().ino, ino);
}

#[test]
fn a_rename_over_an_existing_name_replaces_it() {
    let mut v = vol();
    let keep = v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    v.create(ROOT_INO, b"b", &spec(S_IFREG | 0o644), None).unwrap();
    mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", 0).unwrap();
    let v = remount(v);
    assert_eq!(find(&v, b"a").err(), Some(Errno::Enoent));
    assert_eq!(find(&v, b"b").unwrap().ino, keep);
}

#[test]
fn a_rename_that_refuses_to_replace_reports_the_clash() {
    let mut v = vol();
    v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    v.create(ROOT_INO, b"b", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", RENAME_NOREPLACE).err(),
               Some(Errno::Eexist));
    assert!(find(&v, b"a").is_ok());
}

#[test]
fn renaming_a_name_onto_itself_changes_nothing() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"a", 0).unwrap();
    assert_eq!(find(&v, b"a").unwrap().ino, ino);
}

#[test]
fn a_rename_across_directories_moves_the_name_and_fixes_the_parent() {
    let mut v = vol();
    let src = v.create(ROOT_INO, b"src", &spec(S_IFDIR | 0o755), None).unwrap();
    let dst = v.create(ROOT_INO, b"dst", &spec(S_IFDIR | 0o755), None).unwrap();
    let moved = v.create(src, b"m", &spec(S_IFDIR | 0o755), None).unwrap();
    mv(&mut v, src, b"m", dst, b"m", 0).unwrap();
    let v = remount(v);
    assert_eq!(look(&v, src, b"m").err(), Some(Errno::Enoent));
    assert_eq!(look(&v, dst, b"m").unwrap().ino, moved);
    assert_eq!(look(&v, moved, b"..").unwrap().ino, dst);
    assert_eq!(v.read_inode(moved).unwrap().pino, dst);
}

#[test]
fn moving_a_directory_moves_its_link_from_one_parent_to_the_other() {
    let mut v = vol();
    let src = v.create(ROOT_INO, b"src", &spec(S_IFDIR | 0o755), None).unwrap();
    let dst = v.create(ROOT_INO, b"dst", &spec(S_IFDIR | 0o755), None).unwrap();
    v.create(src, b"m", &spec(S_IFDIR | 0o755), None).unwrap();
    let (s0, d0) = (v.read_inode(src).unwrap().links, v.read_inode(dst).unwrap().links);
    mv(&mut v, src, b"m", dst, b"m", 0).unwrap();
    let v = remount(v);
    assert_eq!(v.read_inode(src).unwrap().links, s0 - 1);
    assert_eq!(v.read_inode(dst).unwrap().links, d0 + 1);
}

#[test]
fn a_rename_of_a_file_over_a_directory_is_refused() {
    let mut v = vol();
    v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    assert_eq!(mv(&mut v, ROOT_INO, b"f", ROOT_INO, b"d", 0).err(), Some(Errno::Eisdir));
}

#[test]
fn a_rename_over_a_directory_that_holds_a_name_is_refused() {
    let mut v = vol();
    v.create(ROOT_INO, b"a", &spec(S_IFDIR | 0o755), None).unwrap();
    let b = v.create(ROOT_INO, b"b", &spec(S_IFDIR | 0o755), None).unwrap();
    v.create(b, b"x", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", 0).err(), Some(Errno::Enotempty));
}

// ---------------------------------------------------------------------- flags

#[test]
fn a_flag_this_filesystem_does_not_answer_for_is_refused() {
    let mut v = vol();
    v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    // One bit past the three defined forms.
    assert_eq!(mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", 1 << 3).err(), Some(Errno::Einval));
    // And the refusal happens before anything is touched.
    assert!(find(&v, b"a").is_ok());
    assert_eq!(find(&v, b"b").err(), Some(Errno::Enoent));
}

#[test]
fn an_exchange_cannot_also_refuse_to_replace_or_leave_a_marker() {
    let mut v = vol();
    v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    v.create(ROOT_INO, b"b", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", RENAME_EXCHANGE | RENAME_NOREPLACE).err(),
               Some(Errno::Einval));
    assert_eq!(mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", RENAME_EXCHANGE | RENAME_WHITEOUT).err(),
               Some(Errno::Einval));
}

// ------------------------------------------------------------------- exchange

#[test]
fn an_exchange_crosses_the_two_names_over() {
    let mut v = vol();
    let a = v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    let b = v.create(ROOT_INO, b"b", &spec(S_IFREG | 0o600), None).unwrap();
    assert_ne!(a, b);
    mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", RENAME_EXCHANGE).unwrap();
    let v = remount(v);
    // BOTH sides, or the test passes on a plain rename.
    assert_eq!(find(&v, b"a").unwrap().ino, b);
    assert_eq!(find(&v, b"b").unwrap().ino, a);
    // Neither inode was replaced, so both modes survive under their new names.
    assert_eq!(v.read_inode(a).unwrap().mode, S_IFREG | 0o644);
    assert_eq!(v.read_inode(b).unwrap().mode, S_IFREG | 0o600);
}

#[test]
fn an_exchange_leaves_both_link_counts_alone() {
    let mut v = vol();
    let a = v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    let b = v.create(ROOT_INO, b"b", &spec(S_IFREG | 0o644), None).unwrap();
    v.link(ROOT_INO, b"a2", a, NOW).unwrap();
    let (la, lb) = (v.read_inode(a).unwrap().links, v.read_inode(b).unwrap().links);
    mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", RENAME_EXCHANGE).unwrap();
    let v = remount(v);
    assert_eq!(v.read_inode(a).unwrap().links, la);
    assert_eq!(v.read_inode(b).unwrap().links, lb);
}

#[test]
fn an_exchange_with_a_name_that_does_not_exist_reports_it_missing() {
    let mut v = vol();
    v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"gone", RENAME_EXCHANGE).err(),
               Some(Errno::Enoent));
    assert_eq!(mv(&mut v, ROOT_INO, b"gone", ROOT_INO, b"a", RENAME_EXCHANGE).err(),
               Some(Errno::Enoent));
    assert!(find(&v, b"a").is_ok());
}

#[test]
fn an_exchange_of_a_file_and_a_directory_keeps_the_entry_types_right() {
    let mut v = vol();
    let f = v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    let d = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    mv(&mut v, ROOT_INO, b"f", ROOT_INO, b"d", RENAME_EXCHANGE).unwrap();
    let v = remount(v);
    let at_f = find(&v, b"f").unwrap();
    let at_d = find(&v, b"d").unwrap();
    assert_eq!((at_f.ino, at_f.file_type), (d, FT_DIR));
    assert_eq!((at_d.ino, at_d.file_type), (f, FT_REG_FILE));
}

#[test]
fn an_exchange_across_directories_flips_both_parent_entries() {
    let mut v = vol();
    let x = v.create(ROOT_INO, b"x", &spec(S_IFDIR | 0o755), None).unwrap();
    let y = v.create(ROOT_INO, b"y", &spec(S_IFDIR | 0o755), None).unwrap();
    let a = v.create(x, b"a", &spec(S_IFDIR | 0o755), None).unwrap();
    let b = v.create(y, b"b", &spec(S_IFDIR | 0o755), None).unwrap();
    let (lx, ly) = (v.read_inode(x).unwrap().links, v.read_inode(y).unwrap().links);
    mv(&mut v, x, b"a", y, b"b", RENAME_EXCHANGE).unwrap();
    let v = remount(v);
    assert_eq!(look(&v, x, b"a").unwrap().ino, b);
    assert_eq!(look(&v, y, b"b").unwrap().ino, a);
    // Each moved directory's own parent entry follows it.
    assert_eq!(look(&v, a, b"..").unwrap().ino, y);
    assert_eq!(look(&v, b, b"..").unwrap().ino, x);
    assert_eq!(v.read_inode(a).unwrap().pino, y);
    assert_eq!(v.read_inode(b).unwrap().pino, x);
    // A directory left each parent and a directory arrived, so neither count
    // moves.
    assert_eq!(v.read_inode(x).unwrap().links, lx);
    assert_eq!(v.read_inode(y).unwrap().links, ly);
}

#[test]
fn an_exchange_of_a_mixed_pair_across_directories_moves_one_parent_link() {
    let mut v = vol();
    let x = v.create(ROOT_INO, b"x", &spec(S_IFDIR | 0o755), None).unwrap();
    let y = v.create(ROOT_INO, b"y", &spec(S_IFDIR | 0o755), None).unwrap();
    let d = v.create(x, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    let f = v.create(y, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    let (lx, ly) = (v.read_inode(x).unwrap().links, v.read_inode(y).unwrap().links);
    mv(&mut v, x, b"d", y, b"f", RENAME_EXCHANGE).unwrap();
    let v = remount(v);
    assert_eq!(look(&v, x, b"d").unwrap().ino, f);
    assert_eq!(look(&v, y, b"f").unwrap().ino, d);
    assert_eq!(look(&v, d, b"..").unwrap().ino, y);
    // The directory left `x` and arrived in `y`.
    assert_eq!(v.read_inode(x).unwrap().links, lx - 1);
    assert_eq!(v.read_inode(y).unwrap().links, ly + 1);
}

#[test]
fn an_exchanged_file_has_its_recorded_parent_marked_stale() {
    let mut v = vol();
    let x = v.create(ROOT_INO, b"x", &spec(S_IFDIR | 0o755), None).unwrap();
    let y = v.create(ROOT_INO, b"y", &spec(S_IFDIR | 0o755), None).unwrap();
    let d = v.create(x, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    let f = v.create(y, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    mv(&mut v, x, b"d", y, b"f", RENAME_EXCHANGE).unwrap();
    let v = remount(v);
    // The directory's field is corrected; the file's is declared untrustworthy.
    assert_eq!(v.read_inode(d).unwrap().advise & FADVISE_LOST_PINO_BIT, 0);
    assert_ne!(v.read_inode(f).unwrap().advise & FADVISE_LOST_PINO_BIT, 0);
}

// ------------------------------------------------------------------- whiteout

#[test]
fn a_whiteout_rename_leaves_a_marker_at_the_old_name() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", RENAME_WHITEOUT).unwrap();
    let v = remount(v);
    // The move happened.
    assert_eq!(find(&v, b"b").unwrap().ino, ino);
    // And the old name still exists, as a marker rather than the file.
    let hit = find(&v, b"a").unwrap();
    assert_ne!(hit.ino, ino);
    assert_eq!(hit.file_type, FT_CHRDEV);
    let wo = v.read_inode(hit.ino).unwrap();
    assert_eq!(wo.mode, S_IFCHR);
    assert_eq!(wo.links, 1);
    // A named inode is not on the orphan list any more.
    assert!(!v.is_orphan(hit.ino));
}

#[test]
fn a_whiteout_rename_over_an_existing_name_replaces_it_and_still_marks() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    let old_b = v.create(ROOT_INO, b"b", &spec(S_IFREG | 0o644), None).unwrap();
    mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", RENAME_WHITEOUT).unwrap();
    let v = remount(v);
    assert_eq!(find(&v, b"b").unwrap().ino, ino);
    assert_eq!(find(&v, b"a").unwrap().file_type, FT_CHRDEV);
    assert_ne!(find(&v, b"a").unwrap().ino, old_b);
}

#[test]
fn a_whiteout_belongs_to_whoever_asked_for_the_rename() {
    let mut v = vol();
    v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    let r = Rename { from: ROOT_INO, old: b"a", to: ROOT_INO, new: b"b",
                     flags: RENAME_WHITEOUT, owner: (77, 88), now: NOW };
    v.rename(&r).unwrap();
    let v = remount(v);
    let wo = v.read_inode(find(&v, b"a").unwrap().ino).unwrap();
    assert_eq!((wo.uid, wo.gid), (77, 88));
}

#[test]
fn a_refused_whiteout_rename_leaves_no_inode_behind() {
    let mut v = vol();
    v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    let before = v.read_inode(ROOT_INO).unwrap();
    let inodes = v.valid_inode_count;
    // A file cannot replace a directory, and the refusal must come before the
    // marker's inode is taken.
    assert_eq!(mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"d", RENAME_WHITEOUT).err(),
               Some(Errno::Eisdir));
    assert_eq!(v.valid_inode_count, inodes, "a refused rename took an inode");
    assert!(v.orphan_list().is_empty());
    assert_eq!(v.read_inode(ROOT_INO).unwrap().links, before.links);
    assert_eq!(find(&v, b"a").unwrap().file_type, FT_REG_FILE);
}

#[test]
fn a_renamed_file_has_its_recorded_parent_marked_stale() {
    let mut v = vol();
    let f = v.create(ROOT_INO, b"a", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(v.read_inode(f).unwrap().advise & FADVISE_LOST_PINO_BIT, 0);
    mv(&mut v, ROOT_INO, b"a", ROOT_INO, b"b", 0).unwrap();
    let v = remount(v);
    assert_ne!(v.read_inode(f).unwrap().advise & FADVISE_LOST_PINO_BIT, 0);
}

#[test]
fn a_directory_moved_out_from_under_a_marker_cannot_trust_its_parent_either() {
    let mut v = vol();
    let src = v.create(ROOT_INO, b"src", &spec(S_IFDIR | 0o755), None).unwrap();
    let dst = v.create(ROOT_INO, b"dst", &spec(S_IFDIR | 0o755), None).unwrap();
    let moved = v.create(src, b"m", &spec(S_IFDIR | 0o755), None).unwrap();
    mv(&mut v, src, b"m", dst, b"m", RENAME_WHITEOUT).unwrap();
    let v = remount(v);
    // The marker now holds the old name, so the recorded parent no longer
    // identifies an entry that can be restored from it.
    assert_ne!(v.read_inode(moved).unwrap().advise & FADVISE_LOST_PINO_BIT, 0);
    assert_eq!(look(&v, src, b"m").unwrap().file_type, FT_CHRDEV);
    assert_eq!(look(&v, dst, b"m").unwrap().ino, moved);
    assert_eq!(look(&v, moved, b"..").unwrap().ino, dst);
}

#[test]
fn dot_and_dotdot_are_never_renamed() {
    let mut v = vol();
    let d = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    assert_eq!(mv(&mut v, d, b".", ROOT_INO, b"x", 0).err(), Some(Errno::Einval));
    assert_eq!(mv(&mut v, d, b"..", ROOT_INO, b"x", 0).err(), Some(Errno::Einval));
    assert_eq!(mv(&mut v, ROOT_INO, b"d", d, b"..", 0).err(), Some(Errno::Einval));
}
