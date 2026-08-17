//! What a newly created file is compressed with, proved by REMOUNTING.
//!
//! Every case writes the image, mounts its bytes again, and reads the inode
//! back. Asserting inside the mount that made it would pass on a decision
//! that reached memory and nothing else — and the settings' whole purpose is
//! to be there when the file is next opened.

use alloc::string::String;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::compress::algo::{level, COMPRESS_LZ4, COMPRESS_LZO, COMPRESS_ZSTD};
use crate::flags::{FEATURE_COMPRESSION, F2FS_COMPR_FL, F2FS_NOCOMP_FL, INLINE_DATA};
use crate::mode::{S_IFDIR, S_IFREG};
use crate::node::inode::Inode;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{BLKSIZE, I_FLAGS};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 500);

/// # C: O(1)
fn spec(mode: u16) -> NewInode { NewInode { mode, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// The options a mount of a compressing volume runs with, derived the way a
/// real mount derives them: the volume's facts first, then the line.
/// # C: O(len)
fn opts(feature: u32, line: &str) -> Options {
    let facts = crate::opts::Facts::plain(feature, test_image::SEG_MAIN);
    crate::consistency::resolve(&facts, line).expect("line").0
}

/// A writable volume carrying the compression feature, its hot list, and the
/// options `line` asks for. # C: O(image bytes)
fn vol(hot: &[&str], line: &str) -> Volume<MemImage> {
    let feature = test_image::DEFAULT_FEATURE | FEATURE_COMPRESSION;
    let mut b = test_image::with_root();
    b.feature = feature;
    b.hot_ext = hot.iter().map(|e| String::from(*e)).collect();
    b.mount_opts(opts(feature, line)).expect("mount")
}

/// Commit and mount the same bytes again, under the same options.
/// # C: O(image bytes)
fn remount(v: Volume<MemImage>, line: &str) -> Volume<MemImage> {
    let mut v = v;
    let feature = v.super_block().feature;
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), opts(feature, line), true)
        .unwrap()
}

/// Create a file the way ordinary file creation does — handing the name to
/// the compression policy — then read it back from the medium.
/// # C: O(image bytes)
fn created(hot: &[&str], line: &str, name: &[u8]) -> Inode {
    let mut v = vol(hot, line);
    let ino = v.create_named(ROOT_INO, name, &spec(S_IFREG | 0o644), None).unwrap();
    remount(v, line).read_inode(ino).unwrap()
}

/// Whether the inode came out marked compressed. # C: O(1)
fn compressed(i: &Inode) -> bool { i.flags & F2FS_COMPR_FL != 0 }

#[test]
fn a_named_extension_makes_the_file_compressed_and_the_settings_survive() {
    let i = created(&[], "compress_extension=txt,compress_algorithm=zstd:9,\
                         compress_log_size=6,compress_chksum", b"report.txt");
    assert!(compressed(&i));
    assert_eq!(i.compress_algorithm, COMPRESS_ZSTD);
    assert_eq!(i.log_cluster_size, 6);
    assert_eq!(level(i.compress_flag), 9);
    assert!(crate::compress::algo::checksummed(i.compress_flag));
}

#[test]
fn a_name_no_list_mentions_is_created_plain() {
    let i = created(&[], "compress_extension=txt", b"report.bin");
    assert!(!compressed(&i));
    assert_eq!(i.compress_algorithm, 0);
    assert_eq!(i.log_cluster_size, 0);
    assert_eq!(i.compress_flag, 0);
}

#[test]
fn the_defaults_a_mount_that_named_only_an_extension_stamps() {
    let i = created(&[], "compress_extension=txt", b"a.txt");
    assert!(compressed(&i));
    assert_eq!(i.compress_algorithm, COMPRESS_LZ4);
    assert_eq!(i.log_cluster_size, 2);
    assert_eq!(i.compress_flag, 0);
}

#[test]
fn a_codec_with_no_level_stores_none_however_the_line_named_it() {
    let i = created(&[], "compress_extension=txt,compress_algorithm=lzo", b"a.txt");
    assert_eq!(i.compress_algorithm, COMPRESS_LZO);
    assert_eq!(level(i.compress_flag), 0);
}

#[test]
fn a_refused_extension_is_created_plain_even_under_the_wildcard() {
    let line = "compress_extension=*,nocompress_extension=bin";
    assert!(compressed(&created(&[], line, b"a.txt")));
    assert!(!compressed(&created(&[], line, b"a.bin")));
}

#[test]
fn a_name_the_volume_calls_hot_is_not_compressed() {
    // The volume's own hot list, not the mount's — a property of the medium
    // that a mount line asking for everything must not override.
    let line = "compress_extension=*";
    assert!(!compressed(&created(&["db"], line, b"index.db")));
    assert!(compressed(&created(&["db"], line, b"index.txt")));
}

// ---- inheritance ---------------------------------------------------------

/// Mark `ino`'s stored flag word with `bits`, through the same path
/// `chattr` takes.
///
/// Not by writing the word directly: adding the compressing mark has to stamp
/// the codec and cluster width with it, and an inode carrying the mark and no
/// width is one the format does not admit. Marking the fixture by hand would
/// build exactly that inode and test against something no mount can produce.
/// # C: O(1 block)
fn mark(v: &mut Volume<MemImage>, ino: u32, bits: u32) {
    let flags = v.read_inode(ino).unwrap().flags | bits;
    if bits & F2FS_COMPR_FL != 0 && bits & F2FS_NOCOMP_FL != 0 {
        // The pair is refused as one word, so it is reached the only way it
        // can be: the compressing mark first, the refusing one added after.
        v.set_inode_flags(ino, flags & !F2FS_NOCOMP_FL).unwrap();
        v.stamp_inode(ino, |b| crate::volume::dnode::put32(b, I_FLAGS, flags)).unwrap();
        return;
    }
    v.set_inode_flags(ino, flags).unwrap();
}

/// A file created under a directory carrying `bits`. # C: O(image bytes)
fn under_marked_dir(bits: u32, line: &str, name: &[u8], named: bool) -> Inode {
    let mut v = vol(&[], line);
    let dir = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    mark(&mut v, dir, bits);
    let s = spec(S_IFREG | 0o644);
    let ino = if named { v.create_named(dir, name, &s, None).unwrap() }
              else { v.create(dir, name, &s, None).unwrap() };
    remount(v, line).read_inode(ino).unwrap()
}

#[test]
fn a_file_under_a_compressing_directory_inherits_the_mounts_settings() {
    let i = under_marked_dir(F2FS_COMPR_FL, "compress_algorithm=zstd:4", b"anything", true);
    assert!(compressed(&i));
    assert_eq!(i.compress_algorithm, COMPRESS_ZSTD);
    assert_eq!(level(i.compress_flag), 4);
}

#[test]
fn a_file_under_a_refusing_directory_carries_the_refusal_onward() {
    let i = under_marked_dir(F2FS_NOCOMP_FL, "", b"anything", true);
    assert!(!compressed(&i));
    assert_ne!(i.flags & F2FS_NOCOMP_FL, 0, "the refusal must be recorded, not just obeyed");
}

#[test]
fn the_refusing_mark_beats_the_compressing_one_on_the_same_directory() {
    let i = under_marked_dir(F2FS_COMPR_FL | F2FS_NOCOMP_FL, "", b"anything", true);
    assert!(!compressed(&i));
    assert_ne!(i.flags & F2FS_NOCOMP_FL, 0);
}

#[test]
fn a_directory_inherits_both_marks_from_its_own_parent() {
    for (bits, want_compr) in [(F2FS_COMPR_FL, true), (F2FS_NOCOMP_FL, false)] {
        let line = "";
        let mut v = vol(&[], line);
        let outer = v.create(ROOT_INO, b"o", &spec(S_IFDIR | 0o755), None).unwrap();
        mark(&mut v, outer, bits);
        let inner = v.create(outer, b"i", &spec(S_IFDIR | 0o755), None).unwrap();
        let i = remount(v, line).read_inode(inner).unwrap();
        assert_eq!(compressed(&i), want_compr, "{bits:#x}");
        assert_eq!(i.flags & F2FS_NOCOMP_FL != 0, !want_compr, "{bits:#x}");
    }
}

#[test]
fn an_operation_that_hands_over_no_name_takes_nothing_from_the_directory() {
    // A device node and a symbolic link are created without a name the policy
    // may read, and they do not inherit either.
    let i = under_marked_dir(F2FS_COMPR_FL, "compress_extension=*", b"x.txt", false);
    assert!(!compressed(&i));
    assert_eq!(i.flags & F2FS_NOCOMP_FL, 0);
}

// ---- what compression excludes ------------------------------------------

#[test]
fn a_compressed_file_is_not_also_given_its_bytes_inside_the_inode() {
    // The inline region is read as plain bytes and a compressed file's are
    // not, so the two cannot both hold. The plain file beside it proves the
    // inline offer is still being made at all.
    let plain = created(&[], "compress_extension=txt", b"a.bin");
    assert_ne!(plain.inline & INLINE_DATA, 0, "the inline offer must still be made");
    let compr = created(&[], "compress_extension=txt", b"a.txt");
    assert_eq!(compr.inline & INLINE_DATA, 0);
}

#[test]
fn a_volume_without_the_feature_compresses_nothing_whatever_the_line_said() {
    let feature = test_image::DEFAULT_FEATURE;
    let mut v = test_image::with_root()
        .mount_opts(opts(feature, "compress_extension=*,compress_algorithm=zstd:9"))
        .expect("mount");
    let ino = v.create_named(ROOT_INO, b"a.txt", &spec(S_IFREG | 0o644), None).unwrap();
    let i = remount(v, "").read_inode(ino).unwrap();
    assert!(!compressed(&i));
    assert_eq!(i.compress_algorithm, 0);
}

// ---- the volume's own list ----------------------------------------------

#[test]
fn the_hot_half_of_the_volumes_extension_list_is_read_back_from_the_medium() {
    // One array holds both temperatures and only the counts separate them.
    // A reader that stops at the cold count finds an empty hot tail, and
    // every decision that consults it then silently sees no hot names.
    let mut b = test_image::with_root();
    b.cold_ext = ["jpg", "mp4"].iter().map(|e| String::from(*e)).collect();
    b.hot_ext = ["db", "log"].iter().map(|e| String::from(*e)).collect();
    let v = b.mount().expect("mount");
    let sb = v.super_block();
    assert_eq!(sb.extension_count, 2);
    assert_eq!(sb.hot_ext_count, 2);
    let all: Vec<&str> = sb.extensions.iter().map(|e| e.as_str()).collect();
    assert_eq!(all, ["jpg", "mp4", "db", "log"]);
}

// ---- the mark set after the fact ----------------------------------------

#[test]
fn marking_an_empty_file_compressed_stamps_the_settings_with_the_mark() {
    // A mark written on its own would leave a stored cluster width of zero,
    // which the format does not admit — the inode would stop being readable.
    let line = "compress_algorithm=zstd:6,compress_log_size=5";
    let mut v = vol(&[], line);
    let ino = v.create_named(ROOT_INO, b"a.bin", &spec(S_IFREG | 0o644), None).unwrap();
    assert!(!compressed(&v.read_inode(ino).unwrap()));
    v.set_inode_flags(ino, F2FS_COMPR_FL).unwrap();
    let i = remount(v, line).read_inode(ino).unwrap();
    assert!(compressed(&i));
    assert_eq!(i.compress_algorithm, COMPRESS_ZSTD);
    assert_eq!(i.log_cluster_size, 5);
    assert_eq!(level(i.compress_flag), 6);
    // And the file it produced is one a fresh mount will read: the check the
    // inode is subjected to on the way in is what a bare mark would fail.
    assert_eq!(i.inline & INLINE_DATA, 0);
}

#[test]
fn marking_a_file_that_holds_blocks_is_refused_in_both_directions() {
    let line = "compress_extension=txt";
    let mut v = vol(&[], line);
    let ino = v.create_named(ROOT_INO, b"a.bin", &spec(S_IFREG | 0o644), None).unwrap();
    v.write_file(ino, 0, &[7u8; BLKSIZE * 2]).unwrap();
    assert_eq!(v.set_inode_flags(ino, F2FS_COMPR_FL), Err(syscall::errno::Errno::Einval));

    let compr = v.create_named(ROOT_INO, b"b.txt", &spec(S_IFREG | 0o644), None).unwrap();
    assert!(compressed(&v.read_inode(compr).unwrap()));
    v.write_file(compr, 0, &[7u8; BLKSIZE * 2]).unwrap();
    assert_eq!(v.set_inode_flags(compr, 0), Err(syscall::errno::Errno::Einval));
}

#[test]
fn a_volume_without_the_feature_refuses_the_mark_rather_than_writing_it() {
    let feature = test_image::DEFAULT_FEATURE;
    let mut v = test_image::with_root().mount_opts(opts(feature, "")).expect("mount");
    let ino = v.create_named(ROOT_INO, b"a.bin", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(v.set_inode_flags(ino, F2FS_COMPR_FL),
               Err(syscall::errno::Errno::Eopnotsupp));
    assert_eq!(v.set_inode_flags(ino, F2FS_NOCOMP_FL),
               Err(syscall::errno::Errno::Eopnotsupp));
}

#[test]
fn the_two_marks_together_are_refused_rather_than_written() {
    let mut v = vol(&[], "");
    let ino = v.create_named(ROOT_INO, b"a.bin", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(v.set_inode_flags(ino, F2FS_COMPR_FL | F2FS_NOCOMP_FL),
               Err(syscall::errno::Errno::Einval));
    assert_eq!(v.read_inode(ino).unwrap().flags, 0);
}
