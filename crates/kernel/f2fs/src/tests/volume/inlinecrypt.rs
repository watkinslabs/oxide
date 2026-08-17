//! `inlinecrypt`, driven through the interface the kernel uses.
//!
//! The unit tests under `crypto/inline` prove the choice and prove the two
//! implementations agree. This proves the choice is REACHED: that the mount
//! option changes which layer encrypts, that a file written under it reads
//! back, and — the one that matters — that the bytes ON THE MEDIUM are
//! identical either way.
//!
//! That last claim is what makes the option safe to turn on. A volume written
//! with it must be readable without it, on a machine with different hardware,
//! forever. Nothing else here would notice if it were not: both mounts decrypt
//! their own output perfectly.

use alloc::vec::Vec;

use super::*;
use sectors::MemImage;
use crate::volume::Volume;
use crate::test_image::ROOT_INO;
use crate::crypto::policy::{Context, KeyId, Policy};
use crate::crypto::uapi::*;
use crate::crypto::MasterKey;
use crate::opts::Options;
use crate::test_image::with_root;

fn master_bytes() -> [u8; 64] { core::array::from_fn(|i| (0x40 + i) as u8) }
fn nonce() -> [u8; FILE_NONCE_SIZE] { core::array::from_fn(|i| (0x10 + i) as u8) }

/// The file's policy: contents by the tweakable mode, which is the one pairing
/// every controller that does inline encryption implements.
fn policy() -> Policy {
    Policy {
        version: POLICY_V2,
        contents_mode: MODE_AES_256_XTS,
        filenames_mode: MODE_AES_256_CTS,
        flags: FLAGS_PAD_4,
        log2_data_unit_size: 0,
        key: KeyId::Identifier(MasterKey::new(&master_bytes()).unwrap().identifier()),
    }
}

/// A file with the policy above attached, on a live read-write volume.
///
/// Built through the allocator rather than laid out by hand, so the blocks the
/// write lands on are real blocks the volume accounted for — the point of the
/// test is what reaches the medium, and a hand-placed image would not exercise
/// the path that puts it there.
/// # C: O(image bytes)
fn encrypted_file(inlinecrypt: bool) -> (Volume<MemImage>, u32) {
    let mut v = crate::test_image::with_root().mount_opts(opts(inlinecrypt)).unwrap();
    let spec = crate::volume::NewInode {
        mode: crate::mode::S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0,
        now: (1_800_000_000, 0),
    };
    let ino = v.create(ROOT_INO, b"f", &spec, None).unwrap();
    attach_policy(&mut v, ino);
    v.add_encryption_key(&master_bytes()).unwrap();
    (v, ino)
}

/// Put the context on an inode and mark it encrypted, the way setting a policy
/// on a directory does — reached here directly because a newly created file
/// does not yet take its parent's policy. # C: O(attribute write)
fn attach_policy(v: &mut Volume<MemImage>, ino: u32) {
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
        // A newly created file holds its first bytes inside its own inode
        // block; an encrypted one never may, because those bytes are not on a
        // block the contents encryption addresses. A file created UNDER a
        // policy is made without it, which is the state reproduced here.
        b[crate::uapi::I_INLINE] &= !(crate::flags::INLINE_DATA | crate::flags::DATA_EXIST);
    }).unwrap();
}

fn opts(inlinecrypt: bool) -> Options {
    let mut o = Options::defaults();
    o.inlinecrypt = inlinecrypt;
    o
}

/// The payload every case writes: one whole block of recognisable bytes.
fn payload() -> Vec<u8> { (0..BLKSIZE).map(|i| (i % 251) as u8).collect() }

/// Write the payload through a mount with or without the option, and hand
/// back the whole medium. # C: O(image bytes)
fn write_through(inlinecrypt: bool) -> (Vec<u8>, Vec<u8>) {
    let (mut v, ino) = encrypted_file(inlinecrypt);
    let data = payload();
    assert_eq!(v.write_file(ino, 0, &data).unwrap(), data.len());

    // Read it back on the same mount: whichever layer encrypted it must be
    // able to undo it.
    let inode = v.read_inode(ino).unwrap();
    let mut back = alloc::vec![0u8; data.len()];
    assert_eq!(v.read_file(&inode, ino, 0, &mut back).unwrap(), data.len());
    assert_eq!(back, data, "the file did not read back");

    v.commit().unwrap();
    (v.into_source().snapshot(), data)
}

/// Mount a medium again under the other setting, with the key. # C: O(bytes)
fn remount(bytes: Vec<u8>, inlinecrypt: bool) -> Volume<MemImage> {
    let mut v = Volume::mount_with(
        MemImage::from_bytes(BLKSIZE as u32, bytes), opts(inlinecrypt), true).unwrap();
    v.add_encryption_key(&master_bytes()).unwrap();
    v
}

/// The inode number `encrypted_file` gives the file it creates. # C: O(1)
fn file_ino(v: &Volume<MemImage>) -> u32 {
    let root = v.read_inode(ROOT_INO).unwrap();
    v.lookup(&root, ROOT_INO, b"f").unwrap().ino
}

#[test]
fn the_option_changes_which_layer_encrypts() {
    let v = crate::test_image::with_root().mount_opts(opts(true)).unwrap();
    assert!(v.options().inlinecrypt);
    // Nothing under this volume does inline encryption in hardware, so the
    // software fallback is what serves it — and it is still inline crypto as
    // far as the filesystem is concerned: this layer no longer touches the
    // bytes.
    assert!(v.inline_crypto().enabled);
    assert!(v.inline_crypto().profile.is_none());

    let off = crate::test_image::with_root().mount_opts(opts(false)).unwrap();
    assert!(!off.inline_crypto().enabled);
}

#[test]
fn a_file_written_with_the_option_is_byte_identical_to_one_written_without() {
    let (with, data) = write_through(true);
    let (without, _) = write_through(false);
    // The whole medium, not just the data block: an out-of-place write also
    // moves metadata, and a difference anywhere would mean the option changed
    // something it has no business changing.
    assert_eq!(with, without,
        "the medium differs — a volume written one way would not read the other");
    // And neither one is the plaintext.
    assert!(!with.windows(data.len()).any(|w| w == data.as_slice()),
        "the file's own bytes are on the medium");
}

#[test]
fn a_file_written_with_the_option_reads_back_without_it() {
    // The case a user actually meets: the disk moves to a machine whose kernel
    // was not asked for inline encryption, or whose hardware cannot do it.
    let (medium, data) = write_through(true);
    let again = remount(medium, false);
    let ino = file_ino(&again);
    let inode = again.read_inode(ino).unwrap();
    let mut back = alloc::vec![0u8; data.len()];
    assert_eq!(again.read_file(&inode, ino, 0, &mut back).unwrap(), data.len());
    assert_eq!(back, data);
}

#[test]
fn a_file_written_without_the_option_reads_back_with_it() {
    let (medium, data) = write_through(false);
    let again = remount(medium, true);
    let ino = file_ino(&again);
    let inode = again.read_inode(ino).unwrap();
    let mut back = alloc::vec![0u8; data.len()];
    assert_eq!(again.read_file(&inode, ino, 0, &mut back).unwrap(), data.len());
    assert_eq!(back, data);
}

#[test]
fn a_partial_write_over_an_existing_block_still_round_trips() {
    // The read-modify-write path: the block on the medium is read back as
    // plaintext, patched, and written again — and with the option the reading
    // and the writing are both done a layer down.
    let (mut v, ino) = encrypted_file(true);
    let mut want = payload();
    v.write_file(ino, 0, &want).unwrap();
    v.write_file(ino, 100, &[0xAAu8; 8]).unwrap();
    want[100..108].fill(0xAA);

    let inode = v.read_inode(ino).unwrap();
    let mut back = alloc::vec![0u8; want.len()];
    v.read_file(&inode, ino, 0, &mut back).unwrap();
    assert_eq!(back, want);
}

#[test]
fn an_encrypted_file_without_its_key_is_still_refused_under_the_option() {
    // The option changes who encrypts, never whether a key is needed.
    let (v, ino) = encrypted_file(true);
    let data = payload();
    let (medium, _) = { let (mut w, i) = encrypted_file(true);
        w.write_file(i, 0, &data).unwrap(); w.commit().unwrap();
        (w.into_source().snapshot(), i) };
    let _ = (v, ino);
    // A mount that never had the key.
    let locked = Volume::mount_with(
        MemImage::from_bytes(BLKSIZE as u32, medium), opts(true), true).unwrap();
    let i = file_ino(&locked);
    let inode = locked.read_inode(i).unwrap();
    let mut back = alloc::vec![0u8; 16];
    assert_eq!(locked.read_file(&inode, i, 0, &mut back).err(),
               Some(syscall::errno::Errno::Enokey));
}



#[test]
fn truncating_inside_a_block_zeroes_the_tail_of_the_plaintext() {
    // The tail zeroing has to happen over the file's own bytes. Doing it over
    // the ciphertext and writing that back encrypts the block a second time:
    // the tail is not zeroes, the rest is noise, and every layer reports
    // success. Checked under both settings, because either layer could get it
    // wrong on its own.
    for inlinecrypt in [false, true] {
        let (mut v, ino) = encrypted_file(inlinecrypt);
        let data = payload();
        v.write_file(ino, 0, &data).unwrap();
        v.truncate_file(ino, 100).unwrap();
        // Grow it back so the whole block is readable again; the bytes past
        // the old length must be zeroes, not what was there before.
        v.write_file(ino, BLKSIZE as u64 - 1, &[0u8; 1]).unwrap();

        let inode = v.read_inode(ino).unwrap();
        let mut back = alloc::vec![0u8; BLKSIZE];
        v.read_file(&inode, ino, 0, &mut back).unwrap();
        assert_eq!(&back[..100], &data[..100], "inlinecrypt={inlinecrypt}");
        assert!(back[100..].iter().all(|&b| b == 0),
                "the truncated tail is not zeroes (inlinecrypt={inlinecrypt})");
    }
}
