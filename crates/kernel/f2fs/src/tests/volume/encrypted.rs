//! An encrypted directory, driven through the interface the kernel uses.
//!
//! The unit tests under `crypto` prove the construction. This proves the
//! construction is REACHED: a volume whose root is encrypted, entries whose
//! stored names are ciphertext, and the three states a caller can be in — no
//! key, key added, key removed again. A module that only its own tests call
//! is a module the filesystem does not use, however green it is.

use alloc::vec::Vec;

use super::*;
use crate::crypto::policy::{Context, KeyId, Policy};
use crate::crypto::uapi::*;
use crate::crypto::MasterKey;

/// The master key this image's root is encrypted under.
fn master_bytes() -> [u8; 64] { core::array::from_fn(|i| (0x40 + i) as u8) }
fn nonce() -> [u8; FILE_NONCE_SIZE] { core::array::from_fn(|i| (0x10 + i) as u8) }

/// A v2 policy naming the key above, with the narrowest padding.
fn policy() -> Policy {
    let mk = MasterKey::new(&master_bytes()).unwrap();
    Policy {
        version: POLICY_V2,
        contents_mode: MODE_AES_256_XTS,
        filenames_mode: MODE_AES_256_CTS,
        flags: FLAGS_PAD_4,
        log2_data_unit_size: 0,
        key: KeyId::Identifier(mk.identifier()),
    }
}

/// The encryption a directory inode would have if the key were present, used
/// only to produce the ciphertext this image stores.
fn dir_info(ino: u32) -> crate::crypto::Info {
    let facts = crate::crypto::InodeFacts {
        is_dir: true, is_reg: false, is_symlink: false, casefolded: false,
    };
    let fs = crate::crypto::FsFacts { max_file_bytes: 1 << 42, blkbits: BLKSIZE_BITS as u8 };
    crate::crypto::Info::setup(
        &Context { policy: policy(), nonce: nonce() },
        &facts, &fs, &MasterKey::new(&master_bytes()).unwrap(), &[0u8; 16], ino).unwrap()
}

/// An image whose root is an encrypted directory holding `names`, with the
/// context in an attribute block the way the format stores it.
fn image(names: &[&[u8]]) -> Builder {
    let mut b = Builder::new();
    let info = dir_info(ROOT_INO);
    let mut s = nodes::Spec::dir(ROOT_INO);
    s.flags |= F2FS_ENCRYPT_FL;
    s.inline |= INLINE_DENTRY | INLINE_DATA | DATA_EXIST;
    s.xattr_nid = 100;
    let (at, len) = nodes::inline_span(&s);
    let layout = crate::dirent::Layout::inline(len);
    let mut all = nodes::dots(ROOT_INO, ROOT_INO);
    for (i, n) in names.iter().enumerate() {
        let ct = info.encrypt_name(n).unwrap();
        all.push(nodes::Ent { name: ct, ino: 10 + i as u32, file_type: FT_REG_FILE });
    }
    let area = nodes::dentry_area(&layout, &all);
    let mut block = nodes::inode_block(&s);
    block[at..at + len].copy_from_slice(&area);
    nodes::place_inode(&mut b, &s, block, 2);
    let (ctx, n) =
        crate::crypto::policy::serialize(&Context { policy: policy(), nonce: nonce() });
    nodes::add_xattr_block(&mut b, ROOT_INO, 100,
        &[(XATTR_INDEX_ENCRYPTION, Vec::from(XATTR_NAME), Vec::from(&ctx[..n]))]);
    b
}

/// Without the key a listing still works: it reports the encoded records a
/// later lookup decodes back — not the ciphertext, and not an error.
#[test]
fn a_locked_directory_lists_names_that_still_find_their_entries() {
    let v = image(&[b"secret.txt"]).mount().unwrap();
    let root = v.root().unwrap();
    assert!(root.encrypted());
    let list = v.read_dir(&root, ROOT_INO).unwrap();
    let shown: Vec<&[u8]> = list.iter().map(|e| &e.name[..]).collect();
    assert!(shown.contains(&&b"."[..]));
    assert!(shown.contains(&&b".."[..]));
    let other: Vec<&crate::DirEntry> =
        list.iter().filter(|e| e.name != b"." && e.name != b"..").collect();
    assert_eq!(other.len(), 1);
    let shown_name = other[0].name.clone();
    // Neither the plaintext nor the raw ciphertext, and made only of
    // characters a directory entry may hold.
    assert_ne!(shown_name, b"secret.txt");
    assert!(shown_name.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
    // And it is a name that finds the entry again, which is the whole point
    // of presenting one rather than refusing.
    assert_eq!(v.lookup(&root, ROOT_INO, &shown_name).unwrap().ino, 10);
    // The plaintext does NOT, since the directory is locked.
    assert_eq!(v.lookup(&root, ROOT_INO, b"secret.txt").err(), Some(Errno::Enoent));
}

/// With the key the same directory lists and resolves plaintext.
#[test]
fn adding_the_key_makes_the_names_plaintext() {
    let mut v = image(&[b"secret.txt", b"another"]).mount().unwrap();
    v.add_encryption_key(&master_bytes()).unwrap();
    let root = v.root().unwrap();
    let mut names: Vec<Vec<u8>> =
        v.read_dir(&root, ROOT_INO).unwrap().into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, alloc::vec![b".".to_vec(), b"..".to_vec(),
                                  b"another".to_vec(), b"secret.txt".to_vec()]);
    assert_eq!(v.lookup(&root, ROOT_INO, b"secret.txt").unwrap().ino, 10);
    assert_eq!(v.lookup(&root, ROOT_INO, b"another").unwrap().ino, 11);
    assert_eq!(v.lookup(&root, ROOT_INO, b"missing").err(), Some(Errno::Enoent));
}

/// Removing the key puts the directory back where it started.
#[test]
fn removing_the_key_returns_the_encoded_names() {
    let mut v = image(&[b"secret.txt"]).mount().unwrap();
    let id = v.add_encryption_key(&master_bytes()).unwrap();
    let root = v.root().unwrap();
    assert!(v.read_dir(&root, ROOT_INO).unwrap().iter().any(|e| e.name == b"secret.txt"));
    assert!(v.remove_encryption_key(&id));
    assert!(!v.read_dir(&root, ROOT_INO).unwrap().iter().any(|e| e.name == b"secret.txt"));
}

/// A key that is not the one the policy names does not unlock the directory:
/// the identifier catches it, instead of producing names that are not names.
#[test]
fn the_wrong_key_does_not_unlock_the_directory() {
    let mut v = image(&[b"secret.txt"]).mount().unwrap();
    v.add_encryption_key(&[0x11u8; 64]).unwrap();
    let root = v.root().unwrap();
    assert!(!v.read_dir(&root, ROOT_INO).unwrap().iter().any(|e| e.name == b"secret.txt"));
}
