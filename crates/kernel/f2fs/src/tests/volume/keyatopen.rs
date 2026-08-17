//! WHERE an encrypted inode's key is resolved.
//!
//! Not what the cipher does — the `crypto` unit tests own that — but which
//! operation goes to the medium for a policy, and which ones are only allowed
//! to read what it left. Resolving a key means reading an attribute, which
//! means a node read, which takes a page lock that can BLOCK; doing it at the
//! point of use put all of that underneath every partial block write in the
//! filesystem, and underneath the mount's own replay.
//!
//! So each test below is one of two claims: an ENTRY resolves and leaves a
//! record, or an inner path REFUSES rather than resolving. The second kind
//! always also asserts the cache is still empty afterwards — that is the
//! observable that separates "refused" from "went and built one, then failed".

use alloc::vec;
use alloc::vec::Vec;

use super::*;
use super::encrypted::{image, master_bytes, nonce, policy};
use crate::crypto::policy::Context;
use crate::crypto::uapi::XATTR_NAME;
use crate::uapi::XATTR_INDEX_ENCRYPTION;
use crate::mode::S_IFREG;
use crate::volume::{NewInode, Volume};
use sectors::MemImage;

const NOW: (u64, u32) = (1_800_000_000, 7);
/// Past the inline region, so the file has real blocks and a partial write of
/// one has something to read back.
const BODY: usize = 2 * BLKSIZE;

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// An encrypted regular file on a writable volume, with the key added unless
/// the caller asked for it to be withheld.
///
/// The context is attached directly because a newly created file does not yet
/// take its parent's policy in this build.
fn encrypted_file(with_key: bool) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"f", &spec(), None).expect("create");
    attach_context(&mut v, ino);
    if with_key { v.add_encryption_key(&master_bytes()).expect("key"); }
    (v, ino)
}

// ---------------------------------------------------------------- the open

#[test]
fn opening_an_encrypted_file_resolves_its_key_once() {
    let (v, ino) = encrypted_file(true);
    let live = v.read_inode(ino).unwrap();
    assert!(!v.crypt_is_held(ino), "nothing resolved before the open");
    v.crypt_file_open(&live, ino).unwrap();
    assert!(v.crypt_is_held(ino), "the open is what resolves it");
    // Idempotent: a second open of the same file costs nothing and changes
    // nothing.
    v.crypt_file_open(&live, ino).unwrap();
    assert!(v.crypt_is_held(ino));
}

#[test]
fn opening_an_encrypted_file_without_its_key_is_refused() {
    let (v, ino) = encrypted_file(false);
    let live = v.read_inode(ino).unwrap();
    assert_eq!(v.crypt_file_open(&live, ino).err(), Some(Errno::Enokey));
    assert!(!v.crypt_is_held(ino), "and nothing was left behind for a later write to find");
}

#[test]
fn opening_a_file_that_is_not_encrypted_resolves_nothing() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"plain", &spec(), None).unwrap();
    let live = v.read_inode(ino).unwrap();
    v.crypt_file_open(&live, ino).unwrap();
    assert!(!v.crypt_is_held(ino));
}

// -------------------------------------------------- the entries that resolve

#[test]
fn a_write_resolves_the_key_at_its_entry_and_not_per_block() {
    let (mut v, ino) = encrypted_file(true);
    let body: Vec<u8> = (0..BODY).map(|i| (i as u8) ^ 0x5A).collect();
    assert_eq!(v.write_file(ino, 0, &body).unwrap(), BODY);
    assert!(v.crypt_is_held(ino), "the write's entry resolved it");
    let live = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&live, ino).unwrap(), body);
}

#[test]
fn a_size_change_resolves_the_key_at_its_entry() {
    let (mut v, ino) = encrypted_file(true);
    let body: Vec<u8> = (0..BODY).map(|i| (i as u8) ^ 0x33).collect();
    v.write_file(ino, 0, &body).unwrap();
    v.flush_data_pages(ino).unwrap();
    // Forgotten first, so the shortening has to resolve it itself. The tail of
    // the last kept block is zeroed over PLAINTEXT and written back, which is
    // the half that needs the key.
    v.crypt_forget(ino);
    v.truncate_file(ino, BLKSIZE as u64 + 7).unwrap();
    assert!(v.crypt_is_held(ino), "the shortening's entry resolved it");
    let live = v.read_inode(ino).unwrap();
    let out = v.read_whole(&live, ino).unwrap();
    assert_eq!(out.len(), BLKSIZE + 7);
    assert_eq!(out[..], body[..BLKSIZE + 7]);
}

#[test]
fn a_read_resolves_the_key_at_its_entry() {
    let (mut v, ino) = encrypted_file(true);
    let body: Vec<u8> = (0..BODY).map(|i| (i as u8) ^ 0x11).collect();
    v.write_file(ino, 0, &body).unwrap();
    v.flush_data_pages(ino).unwrap();
    v.data_cache.forget_inode(ino);
    v.crypt_forget(ino);
    let live = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; BODY];
    assert_eq!(v.read_file(&live, ino, 0, &mut buf).unwrap(), BODY);
    assert_eq!(buf, body);
    assert!(v.crypt_is_held(ino));
}

#[test]
fn a_listing_of_a_locked_directory_resolves_nothing_and_is_not_refused() {
    let mut v = image(&[b"secret.txt"]).mount().unwrap();
    let root = v.root().unwrap();
    // Locked: the listing works and there is nothing to hold.
    assert!(!v.read_dir(&root, ROOT_INO).unwrap().is_empty());
    assert!(!v.crypt_is_held(ROOT_INO));
    // With the key the SAME listing is what resolves it — the reference's
    // readdir hook sets the key up and does not require one.
    v.add_encryption_key(&master_bytes()).unwrap();
    assert!(v.read_dir(&root, ROOT_INO).unwrap().iter().any(|e| e.name == b"secret.txt"));
    assert!(v.crypt_is_held(ROOT_INO));
}

// ------------------------------------------- the inner paths that must not

#[test]
fn a_block_write_consumes_the_record_and_never_builds_one() {
    let (mut v, ino) = encrypted_file(true);
    let body: Vec<u8> = (0..BODY).map(|i| (i as u8) ^ 0x77).collect();
    v.write_file(ino, 0, &body).unwrap();
    // As if this block write had been reached without passing an entry point.
    v.crypt_forget(ino);
    assert_eq!(v.write_one_block(ino, 0, 4, b"zzzz").err(), Some(Errno::Enokey));
    assert!(!v.crypt_is_held(ino),
            "the block write must not go to the medium for a key of its own");
}

#[test]
fn a_writeback_consumes_the_record_and_never_builds_one() {
    let (mut v, ino) = encrypted_file(true);
    let body: Vec<u8> = (0..BODY).map(|i| (i as u8) ^ 0x2B).collect();
    v.write_file(ino, 0, &body).unwrap();
    v.crypt_forget(ino);
    assert_eq!(v.flush_data_pages(ino).err(), Some(Errno::Enokey));
    assert!(!v.crypt_is_held(ino),
            "placing a page must not resolve a key from under the placement");
}

// --------------------------------------------------- the key table changing

#[test]
fn removing_a_key_drops_what_was_resolved_under_it() {
    let (mut v, ino) = encrypted_file(true);
    let body: Vec<u8> = (0..BODY).map(|i| (i as u8) ^ 0x40).collect();
    v.write_file(ino, 0, &body).unwrap();
    assert!(v.crypt_is_held(ino));
    let id = crate::crypto::KeyId::Identifier(
        crate::crypto::MasterKey::new(&master_bytes()).unwrap().identifier());
    assert!(v.remove_encryption_key(&id));
    assert!(!v.crypt_is_held(ino), "a file opened under the key must not stay readable");
    // The buffered write went out BEFORE the key did, so nothing is left that
    // only the removed key could have enciphered.
    assert!(!v.data_cache.dirty_inodes().contains(&ino));
    let live = v.read_inode(ino).unwrap();
    assert_eq!(v.read_file(&live, ino, 0, &mut vec![0u8; BODY]).err(), Some(Errno::Enokey));
}

#[test]
fn a_freed_inode_leaves_no_key_for_the_next_file_to_take() {
    let (mut v, ino) = encrypted_file(true);
    v.write_file(ino, 0, &vec![7u8; BODY]).unwrap();
    v.flush_data_pages(ino).unwrap();
    assert!(v.crypt_is_held(ino));
    v.free_inode(ino).unwrap();
    assert!(!v.crypt_is_held(ino));
}

// ------------------------------------------------------------- the replay

/// A replay needs NO key, and must not encrypt a name that is already
/// encrypted.
///
/// The name a recovered inode carries is the stored form — ciphertext for an
/// encrypted parent — and the mount that replays it runs before any key can
/// have been added. Putting it back through the plaintext path both refused for
/// want of a key and, with one, filed a doubly-encrypted name nothing could
/// ever find.
#[test]
fn a_name_is_put_back_into_a_locked_directory_without_a_key_and_without_re_encrypting() {
    let mut v = image(&[]).mount_rw().unwrap();
    let id = v.add_encryption_key(&master_bytes()).unwrap();
    let root = v.root().unwrap();
    let info = v.crypt_require_key(&root, ROOT_INO).unwrap().unwrap();
    let stored = info.encrypt_name(b"recovered").unwrap();
    let want = v.entry_hash_crypt(&root, Some(&info), b"recovered").unwrap();
    // The key goes away, which is the state a mount replaying a chain is in.
    assert!(v.remove_encryption_key(&id));
    assert!(!v.crypt_is_held(ROOT_INO));
    let root = v.root().unwrap();
    v.add_stored_dentry(ROOT_INO, &root, &stored, want, 10, FT_REG_FILE).unwrap();
    assert_eq!(v.find_stored_entry(&root, ROOT_INO, want, &stored).unwrap(), Some(10));
    assert!(!v.crypt_is_held(ROOT_INO), "placing a stored name resolves nothing");
    // And with the key back the entry is the plaintext name. A second round of
    // encryption would leave a name no lookup can produce.
    v.add_encryption_key(&master_bytes()).unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b"recovered").unwrap().ino, 10);
}

/// End to end: a file created and made durable in an encrypted directory, on a
/// volume that then crashes, is reachable by its plaintext name again after the
/// replaying mount is given the key.
#[test]
fn a_crash_in_an_encrypted_directory_replays_and_the_name_is_still_the_plaintext() {
    use crate::volume::recover::fixture::remount_opts;
    let mut v = image(&[]).mount_rw().unwrap();
    v.add_encryption_key(&master_bytes()).unwrap();
    v.commit().unwrap();
    let ino = v.create(ROOT_INO, b"kept", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![0xA5u8; BODY]).unwrap();
    assert_eq!(v.fsync(ino).unwrap(), crate::volume::fsync::CpReason::None);
    let bytes = v.into_source().snapshot();
    // The chain is left standing so the pass can be driven by hand and its
    // report read; the mount holds NO key, exactly as a real one would not.
    let mut v = remount_opts(bytes, true,
        crate::opts::Options { recovery: false, ..crate::opts::Options::defaults() });
    let report = v.recover().unwrap();
    let crate::volume::recover::Recovery::Replayed(done) = report
        else { panic!("the fixture must leave a chain to replay: {report:?}") };
    assert!(done.dentries >= 1, "the entry had to be put back: {done:?}");
    assert!(!v.crypt_is_held(ROOT_INO), "and the replay resolved no key at all");
    v.add_encryption_key(&master_bytes()).unwrap();
    let root = v.root().unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b"kept").unwrap().ino, ino);
}

/// The name an inode RECORDS is the stored form, so an encrypted file's
/// plaintext name never reaches the medium — and so a keyless replay has
/// something it can use.
#[test]
fn an_encrypted_files_recorded_name_is_the_ciphertext_and_is_marked_as_such() {
    let mut v = image(&[]).mount_rw().unwrap();
    v.add_encryption_key(&master_bytes()).unwrap();
    let root = v.root().unwrap();
    let info = v.crypt_require_key(&root, ROOT_INO).unwrap().unwrap();
    let ino = v.create(ROOT_INO, b"secret.txt", &spec(), None).unwrap();
    let block = v.inode_bytes(ino).unwrap();
    let len = crate::uapi::le32(&block, I_NAMELEN).unwrap() as usize;
    let held = &block[I_NAME..I_NAME + len];
    assert_ne!(held, b"secret.txt", "the plaintext name is on the medium");
    assert_eq!(held, &info.encrypt_name(b"secret.txt").unwrap()[..]);
    assert_ne!(block[I_ADVISE] & FADVISE_ENC_NAME_BIT, 0);
    // A file in a plain directory still records its plaintext name.
    let mut p = test_image::with_root().mount_rw().unwrap();
    let pino = p.create(ROOT_INO, b"plain.txt", &spec(), None).unwrap();
    let pb = p.inode_bytes(pino).unwrap();
    let plen = crate::uapi::le32(&pb, I_NAMELEN).unwrap() as usize;
    assert_eq!(&pb[I_NAME..I_NAME + plen], b"plain.txt");
    assert_eq!(pb[I_ADVISE] & FADVISE_ENC_NAME_BIT, 0);
}

/// Creating in a LOCKED directory is refused before an inode number is taken,
/// which is where the reference refuses it.
#[test]
fn creating_a_name_in_a_locked_directory_is_refused_and_leaks_no_inode() {
    let mut v = image(&[]).mount_rw().unwrap();
    let before = v.checkpoint().valid_inode_count;
    assert_eq!(v.create(ROOT_INO, b"nope", &spec(), None).err(), Some(Errno::Enokey));
    assert_eq!(v.checkpoint().valid_inode_count, before);
}

/// An atomic span of an encrypted file works off the record its own entry
/// resolved: the span's block writer consumes one and cannot make one.
#[test]
fn an_atomic_span_of_an_encrypted_file_reads_and_writes_its_plaintext() {
    let (mut v, ino) = encrypted_file(true);
    v.write_file(ino, 0, &vec![0x11u8; BODY]).unwrap();
    v.flush_data_pages(ino).unwrap();
    v.start_atomic_write(ino, false).unwrap();
    // Forgotten first, so the span's entry point is what resolves the key.
    v.crypt_forget(ino);
    assert_eq!(v.write_file(ino, 4, b"span").unwrap(), 4);
    assert!(v.crypt_is_held(ino));
    let live = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; 12];
    v.read_file(&live, ino, 0, &mut buf).unwrap();
    assert_eq!(&buf[..4], &[0x11u8; 4]);
    assert_eq!(&buf[4..8], b"span");
    v.commit_atomic_write(ino).unwrap();
    let live = v.read_inode(ino).unwrap();
    let mut after = vec![0u8; 12];
    v.read_file(&live, ino, 0, &mut after).unwrap();
    assert_eq!(after, buf);
}

/// A file that is both compressed and encrypted is refused rather than written
/// in the clear — WITH the key in hand, so the refusal is the combination and
/// not a missing key.
///
/// The key comes first on both paths, which is the reference's order: its
/// setattr hook requires one at the top of a size change, before anything f2fs
/// decides about a compressed file. A file with no key would therefore report
/// that instead, and prove nothing about the combination.
#[test]
fn a_file_that_is_both_compressed_and_encrypted_is_refused_rather_than_written_in_the_clear() {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut v = b.mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"c", &spec(), None).unwrap();
    attach_context(&mut v, ino);
    v.stamp_inode(ino, |b| {
        let f = crate::uapi::le32(b, I_FLAGS).unwrap_or(0) | crate::flags::F2FS_COMPR_FL;
        b[I_FLAGS..I_FLAGS + 4].copy_from_slice(&f.to_le_bytes());
        b[crate::uapi::I_COMPRESS_ALGORITHM] = crate::compress::algo::COMPRESS_LZ4;
        b[crate::uapi::I_LOG_CLUSTER_SIZE] = 2;
    })
    .unwrap();
    v.add_encryption_key(&master_bytes()).unwrap();
    assert_eq!(v.truncate_file(ino, 0).err(), Some(Errno::Eopnotsupp));
    // Refused BEFORE anything reaches the medium, which is the property that
    // matters.
    assert_eq!(v.write_file(ino, 0, b"x").err(), Some(Errno::Eopnotsupp));
    assert_eq!(v.read_inode(ino).unwrap().size, 0);
}

/// A file flagged encrypted and carrying no context reports THAT, from the
/// entry, on both the write and the size change.
#[test]
fn a_write_of_an_encrypted_file_with_no_context_is_refused_at_the_entry() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.stamp_inode(ino, |b| {
        let f = crate::uapi::le32(b, I_FLAGS).unwrap_or(0) | F2FS_ENCRYPT_FL;
        b[I_FLAGS..I_FLAGS + 4].copy_from_slice(&f.to_le_bytes());
    })
    .unwrap();
    assert_eq!(v.write_file(ino, 0, b"x").err(), Some(Errno::Euclean));
    assert_eq!(v.truncate_file(ino, 0).err(), Some(Errno::Euclean));
    assert!(!v.crypt_is_held(ino));
}

/// Put a v2 context on an inode and mark it encrypted, the way setting a policy
/// on a directory does — reached directly because a newly created file does not
/// yet take its parent's policy in this build.
fn attach_context(v: &mut Volume<MemImage>, ino: u32) {
    let inode = v.read_inode(ino).unwrap();
    let (bytes, used) =
        crate::crypto::policy::serialize(&Context { policy: policy(), nonce: nonce() });
    let area = v.xattr_area(&inode, ino).unwrap();
    let mut attrs = crate::xattr::list(&area).unwrap();
    attrs.push(crate::xattr::Attr {
        index: XATTR_INDEX_ENCRYPTION,
        name: XATTR_NAME.to_vec(),
        value: bytes[..used].to_vec(),
    });
    v.store_xattrs(ino, &attrs).unwrap();
    v.stamp_inode(ino, |b| {
        let at = crate::uapi::I_FLAGS;
        let held = u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        crate::volume::dnode::put32(b, at, held | F2FS_ENCRYPT_FL);
        b[I_INLINE] &= !(INLINE_DATA | DATA_EXIST);
    })
    .unwrap();
}
