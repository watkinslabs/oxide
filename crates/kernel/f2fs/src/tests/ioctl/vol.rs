//! The volume operations this surface is the only caller of, driven against a
//! real fixture volume.
//!
//! Each one is checked by READING IT BACK through the ordinary path, and the
//! ones that touch the medium are checked across a remount: a bit set only in
//! the mount's own copy of the inode looks identical to a bit written down,
//! until the next mount.

use crate::mode::{S_IFDIR, S_IFREG};
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 11);

fn spec(mode: u16) -> NewInode {
    NewInode { mode, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// A writable volume holding one empty regular file, and that file's number.
fn one_file() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    (v, ino)
}

/// The same volume remounted from the bytes the first mount wrote.
fn remount(v: Volume<MemImage>) -> Volume<MemImage> {
    let img = v.into_source();
    Volume::mount_with(img, crate::opts::Options::defaults(), true).unwrap()
}

// ---- pinning --------------------------------------------------------------

#[test]
fn a_file_starts_unpinned() {
    let (v, ino) = one_file();
    assert_eq!(v.is_pinned(ino), Ok(false));
}

#[test]
fn pinning_a_file_reads_back_as_pinned() {
    let (mut v, ino) = one_file();
    v.set_pinned(ino, true).unwrap();
    assert_eq!(v.is_pinned(ino), Ok(true));
}

/// The bit is on the MEDIUM, not in the mount: a pin that vanished at unmount
/// would let the cleaner move a file something outside still addresses.
#[test]
fn a_pin_survives_a_remount() {
    let (mut v, ino) = one_file();
    v.set_pinned(ino, true).unwrap();
    v.commit().unwrap();
    let v = remount(v);
    assert_eq!(v.is_pinned(ino), Ok(true));
}

#[test]
fn unpinning_reads_back_as_unpinned() {
    let (mut v, ino) = one_file();
    v.set_pinned(ino, true).unwrap();
    v.set_pinned(ino, false).unwrap();
    assert_eq!(v.is_pinned(ino), Ok(false));
}

/// The promise is about where the blocks ARE, and the ones already written
/// went wherever the log put them.
#[test]
fn pinning_a_file_that_already_holds_blocks_is_refused() {
    let (mut v, ino) = one_file();
    v.write_file(ino, 0, &[7u8; 8192]).unwrap();
    assert_eq!(v.set_pinned(ino, true), Err(Errno::Efbig));
    assert_eq!(v.is_pinned(ino), Ok(false));
}

/// A read-only mount refuses rather than pinning only in memory.
#[test]
fn pinning_on_a_read_only_mount_is_refused() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.set_pinned(ROOT_INO, true), Err(Errno::Erofs));
}

// ---- the label ------------------------------------------------------------

#[test]
fn a_new_label_reads_back_and_survives_a_remount() {
    let (mut v, _) = one_file();
    v.set_label("oxide-data").unwrap();
    assert_eq!(v.label(), "oxide-data");
    v.commit().unwrap();
    let v = remount(v);
    assert_eq!(v.label(), "oxide-data");
}

/// The buffer a query hands back is the fixed size the command declares, with
/// the label at its head and a terminator after it.
#[test]
fn the_label_buffer_is_terminated_inside_the_declared_size() {
    let (mut v, _) = one_file();
    v.set_label("abc").unwrap();
    let b = v.label_buffer();
    assert_eq!(b.len(), crate::ioctl::uapi::FSLABEL_MAX as usize);
    assert_eq!(&b[..3], b"abc");
    assert_eq!(b[3], 0);
}

#[test]
fn a_label_longer_than_the_superblock_holds_is_refused() {
    let (mut v, _) = one_file();
    let long: alloc::string::String =
        core::iter::repeat('x').take(crate::uapi::SB_VOLUME_NAME_UNITS + 1).collect();
    assert_eq!(v.set_label(&long), Err(Errno::Einval));
}

// ---- the change counter ---------------------------------------------------

#[test]
fn the_change_counter_reads_back_and_survives_a_remount() {
    let (mut v, ino) = one_file();
    v.set_generation(ino, 0x1234_5678).unwrap();
    assert_eq!(v.read_inode(ino).unwrap().generation, 0x1234_5678);
    v.commit().unwrap();
    let v = remount(v);
    assert_eq!(v.read_inode(ino).unwrap().generation, 0x1234_5678);
}

// ---- the flag word --------------------------------------------------------

#[test]
fn the_flag_word_reads_back_and_survives_a_remount() {
    let (mut v, ino) = one_file();
    v.set_inode_flags(ino, crate::flags::F2FS_APPEND_FL).unwrap();
    assert_eq!(v.read_inode(ino).unwrap().flags, crate::flags::F2FS_APPEND_FL);
    v.commit().unwrap();
    let v = remount(v);
    assert_eq!(v.read_inode(ino).unwrap().flags, crate::flags::F2FS_APPEND_FL);
}

// ---- the codec pair -------------------------------------------------------

#[test]
fn the_codec_pair_reads_back_and_survives_a_remount() {
    let (mut v, ino) = one_file();
    v.set_compress_option(ino, 1, 4).unwrap();
    assert_eq!(v.compress_option(ino), Ok((1, 4)));
    v.commit().unwrap();
    let v = remount(v);
    assert_eq!(v.compress_option(ino), Ok((1, 4)));
}

/// The cluster size decides what every stored address means, so it cannot
/// change under blocks already written.
#[test]
fn changing_the_codec_under_existing_blocks_is_refused() {
    let (mut v, ino) = one_file();
    v.write_file(ino, 0, &[1u8; 8192]).unwrap();
    assert_eq!(v.set_compress_option(ino, 1, 4), Err(Errno::Efbig));
}

// ---- the feature word -----------------------------------------------------

/// Atomic writes are not recorded as a feature because every volume has them,
/// and a caller testing for them would otherwise never see one.
#[test]
fn the_reported_features_add_atomic_writes_to_the_stored_word() {
    let (v, _) = one_file();
    let stored = v.super_block().feature;
    assert_eq!(v.ioctl_features(), stored | crate::flags::FEATURE_ATOMIC_WRITE);
    assert_ne!(v.ioctl_features() & crate::flags::FEATURE_ATOMIC_WRITE, 0);
}

// ---- keys -----------------------------------------------------------------

#[test]
fn a_key_added_is_held_and_a_key_removed_is_not() {
    let (mut v, _) = one_file();
    let id = v.add_encryption_key(&[0x5a; 32]).unwrap();
    assert!(v.holds_encryption_key(&id));
    assert!(v.remove_encryption_key(&id));
    assert!(!v.holds_encryption_key(&id));
}

/// The newer scheme derives the name FROM the key, so the same key always
/// gets the same name and a different key never does.
#[test]
fn the_derived_key_name_follows_the_key() {
    let (mut v, _) = one_file();
    let a = v.add_encryption_key(&[1u8; 32]).unwrap();
    let b = v.add_encryption_key(&[1u8; 32]).unwrap();
    let c = v.add_encryption_key(&[2u8; 32]).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---- the password salt ----------------------------------------------------

/// The salt is written through before it is reported: a caller that derived a
/// key from a salt the volume then forgot could not open its own files.
#[test]
fn the_password_salt_is_stable_across_calls_and_a_remount() {
    let (mut v, ino) = one_file();
    let first = v.encryption_pwsalt([0xa5; 16]).unwrap();
    assert_eq!(first, [0xa5; 16]);
    // A second ask hands back the salt already stored, not the new one offered.
    assert_eq!(v.encryption_pwsalt([0x11; 16]).unwrap(), [0xa5; 16]);
    v.commit().unwrap();
    let mut v = remount(v);
    assert_eq!(v.encryption_pwsalt([0x22; 16]).unwrap(), [0xa5; 16]);
    let _ = ino;
}

// ---- setting a policy -----------------------------------------------------

fn wire_v2() -> alloc::vec::Vec<u8> {
    crate::ioctl::policy::encode_wire(&crate::crypto::policy::Policy {
        version: crate::crypto::uapi::POLICY_V2,
        contents_mode: crate::crypto::uapi::MODE_AES_256_XTS,
        filenames_mode: crate::crypto::uapi::MODE_AES_256_CTS,
        flags: 0,
        log2_data_unit_size: 0,
        key: crate::crypto::policy::KeyId::Identifier([0x33; 16]),
    })
}

#[test]
fn a_policy_set_on_an_empty_directory_reads_back_through_the_ordinary_path() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let dir = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    v.set_encryption_policy(dir, &wire_v2()).unwrap();
    let inode = v.read_inode(dir).unwrap();
    assert!(inode.encrypted());
    let ctx = v.crypt_context(&inode, dir).unwrap().expect("a context");
    assert_eq!(ctx.policy.key, crate::crypto::policy::KeyId::Identifier([0x33; 16]));
}

/// A file is not a directory: only a directory hands a policy down.
#[test]
fn a_policy_on_something_that_is_not_a_directory_is_refused() {
    let (mut v, ino) = one_file();
    assert_eq!(v.set_encryption_policy(ino, &wire_v2()), Err(Errno::Enotdir));
}

/// An object that ALREADY carries a policy is answered for the policy, before
/// anything about its shape is tested.
///
/// The ordering is the contract a caller reads: a request to set a policy on an
/// object that has one is about the policy, so a non-directory carrying a
/// context hears `EEXIST` and not `ENOTDIR`. Arranged by turning a directory
/// that holds a policy into a file, which the ordinary interface cannot do —
/// the ordering is nonetheless what the answer is defined by.
#[test]
fn an_object_that_already_holds_a_policy_answers_for_the_policy_first() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let dir = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    v.set_encryption_policy(dir, &wire_v2()).unwrap();
    let mode = crate::mode::S_IFREG | 0o644;
    v.stamp_inode(dir, |b| crate::volume::dnode::put16(b, crate::uapi::I_MODE, mode)).unwrap();
    assert!(!v.crypt_inode_facts(&v.read_inode(dir).unwrap()).is_dir, "still a directory");
    let other = crate::ioctl::policy::encode_wire(&crate::crypto::policy::Policy {
        version: crate::crypto::uapi::POLICY_V2,
        contents_mode: crate::crypto::uapi::MODE_AES_256_XTS,
        filenames_mode: crate::crypto::uapi::MODE_AES_256_CTS,
        flags: 0,
        log2_data_unit_size: 0,
        key: crate::crypto::policy::KeyId::Identifier([0x44; 16]),
    });
    assert_eq!(v.set_encryption_policy(dir, &other), Err(Errno::Eexist),
               "the shape was tested before the policy that is already there");
    // And the same policy is still not an error, whatever the object's shape.
    assert_eq!(v.set_encryption_policy(dir, &wire_v2()), Ok(()));
}

/// Re-applying the SAME policy is how a tool makes sure of one it may already
/// have set, and must not be an error.
#[test]
fn setting_the_same_policy_twice_is_not_an_error() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let dir = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    v.set_encryption_policy(dir, &wire_v2()).unwrap();
    assert_eq!(v.set_encryption_policy(dir, &wire_v2()), Ok(()));
}

/// A DIFFERENT policy is a second answer to how the directory's children are
/// written, and the children already there were written under the first.
#[test]
fn setting_a_second_different_policy_is_refused() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let dir = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    v.set_encryption_policy(dir, &wire_v2()).unwrap();
    let other = crate::ioctl::policy::encode_wire(&crate::crypto::policy::Policy {
        version: crate::crypto::uapi::POLICY_V2,
        contents_mode: crate::crypto::uapi::MODE_AES_256_XTS,
        filenames_mode: crate::crypto::uapi::MODE_AES_256_CTS,
        flags: 0,
        log2_data_unit_size: 0,
        key: crate::crypto::policy::KeyId::Identifier([0x44; 16]),
    });
    assert_eq!(v.set_encryption_policy(dir, &other), Err(Errno::Eexist));
}

/// Entries already in the directory were written under no policy and would
/// become unreadable once the key was added.
#[test]
fn a_policy_on_a_directory_that_already_holds_entries_is_refused() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let dir = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    v.create(dir, b"child", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(v.set_encryption_policy(dir, &wire_v2()), Err(Errno::Enotempty));
}

/// A volume advertising lost+found tells a repair tool that the directory it
/// reparents recovered orphans into is reachable. A tool holds no key, so a
/// policy on the ROOT would put the whole tree — that directory included — out
/// of its reach while the volume went on advertising the repair path.
#[test]
fn the_root_of_a_lost_found_volume_may_not_be_given_a_policy() {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_LOST_FOUND;
    let mut v = b.mount_rw().unwrap();
    assert_eq!(v.set_encryption_policy(ROOT_INO, &wire_v2()), Err(Errno::Eperm));
    assert!(!v.read_inode(ROOT_INO).unwrap().encrypted(), "the root was encrypted anyway");
}

/// The refusal is the FEATURE, not the root: a volume that promises no
/// reparenting target has nothing to lose by encrypting its top directory.
#[test]
fn the_root_of_a_volume_without_the_feature_may_be_given_a_policy() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.set_encryption_policy(ROOT_INO, &wire_v2()).unwrap();
    assert!(v.read_inode(ROOT_INO).unwrap().encrypted());
}

/// And it is only the root. A policy anywhere below it leaves every directory
/// above reachable without a key, which is all the repair path needs.
#[test]
fn a_directory_below_the_root_of_a_lost_found_volume_may_be_given_a_policy() {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_LOST_FOUND;
    let mut v = b.mount_rw().unwrap();
    let dir = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    v.set_encryption_policy(dir, &wire_v2()).unwrap();
    assert!(v.read_inode(dir).unwrap().encrypted());
}

/// LAST of the refusals, where the reference puts it: a request that would
/// have been refused for its own shape hears about that instead.
#[test]
fn a_root_that_is_not_empty_is_refused_for_being_full_and_not_for_the_feature() {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_LOST_FOUND;
    let mut v = b.mount_rw().unwrap();
    v.create(ROOT_INO, b"child", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(v.set_encryption_policy(ROOT_INO, &wire_v2()), Err(Errno::Enotempty));
}

/// Two inodes on one volume must never share a nonce, or their derived keys
/// would repeat.
#[test]
fn two_encrypted_directories_get_different_nonces() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let a = v.create(ROOT_INO, b"a", &spec(S_IFDIR | 0o755), None).unwrap();
    let b = v.create(ROOT_INO, b"b", &spec(S_IFDIR | 0o755), None).unwrap();
    v.set_encryption_policy(a, &wire_v2()).unwrap();
    v.set_encryption_policy(b, &wire_v2()).unwrap();
    let ia = v.read_inode(a).unwrap();
    let ib = v.read_inode(b).unwrap();
    let ca = v.crypt_context(&ia, a).unwrap().unwrap();
    let cb = v.crypt_context(&ib, b).unwrap().unwrap();
    assert_ne!(ca.nonce, cb.nonce);
}

// ---- precaching -----------------------------------------------------------

#[test]
fn precaching_walks_every_block_of_a_file() {
    let (mut v, ino) = one_file();
    let blocks = 5usize;
    v.write_file(ino, 0, &alloc::vec![9u8; blocks * crate::uapi::BLKSIZE]).unwrap();
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.precache_extents(&inode, ino), Ok(blocks as u64));
}

#[test]
fn precaching_an_empty_file_walks_nothing() {
    let (v, ino) = one_file();
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.precache_extents(&inode, ino), Ok(0));
}

// ---- trimming free space --------------------------------------------------

/// The granularity is raised to at least one block and reported back, because
/// a caller that asked for less got more.
#[test]
fn trimming_reports_the_granularity_it_actually_used() {
    let (mut v, _) = one_file();
    let (_, granularity) = v.trim_free_space(0, u64::MAX, 0).unwrap();
    assert_eq!(granularity, crate::uapi::BLKSIZE as u64);
    let (_, granularity) = v.trim_free_space(0, u64::MAX, 1 << 20).unwrap();
    assert_eq!(granularity, 1 << 20);
}

/// A whole-volume trim finds free segments; an empty range finds none. The
/// pair is the control: without it a function returning zero always would
/// pass the first half.
#[test]
fn a_whole_volume_trim_offers_space_and_an_empty_range_offers_none() {
    let (mut v, _) = one_file();
    let (whole, _) = v.trim_free_space(0, u64::MAX, 0).unwrap();
    assert!(whole > 0, "a fresh volume has free segments");
    let (empty, _) = v.trim_free_space(0, 0, 0).unwrap();
    assert_eq!(empty, 0);
}

/// A granularity larger than a segment leaves nothing to offer, which is the
/// answer a caller asking for huge runs must get rather than a silent
/// full-volume trim.
#[test]
fn a_granularity_larger_than_a_segment_offers_nothing() {
    let (mut v, _) = one_file();
    let per_seg = u64::from(crate::uapi::BLKS_PER_SEG) * crate::uapi::BLKSIZE as u64;
    let (offered, _) = v.trim_free_space(0, u64::MAX, per_seg + 1).unwrap();
    assert_eq!(offered, 0);
}
