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
pub(super) fn master_bytes() -> [u8; 64] { core::array::from_fn(|i| (0x40 + i) as u8) }
pub(super) fn nonce() -> [u8; FILE_NONCE_SIZE] { core::array::from_fn(|i| (0x10 + i) as u8) }

/// A v2 policy naming the key above, with the narrowest padding.
pub(super) fn policy() -> Policy {
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
pub(super) fn image(names: &[&[u8]]) -> Builder {
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
        let child_ino = 10 + i as u32;
        all.push(nodes::Ent { name: ct, ino: child_ino, file_type: FT_REG_FILE });
        let child = nodes::Spec::file(child_ino);
        nodes::place_inode(&mut b, &child, nodes::inode_block(&child), 1);
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

/// The live volume admission owner, not only the pure policy helper, rejects
/// a plaintext inode beneath an encrypted directory. This is the guard open,
/// link and rename must all share before changing or serving the inode.
#[test]
fn an_encrypted_parent_rejects_a_plaintext_child_at_the_live_boundary() {
    let v = image(&[b"secret.txt"]).mount().unwrap();
    assert_eq!(v.crypt_check_permitted(ROOT_INO, 10), Err(Errno::Eperm));
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

/// A directory that both folds case and encrypts, built the way such a volume
/// really is: names stored as ciphertext, filed under the KEYED hash of the
/// folded plaintext.
fn folding_encrypted_root(names: &[&[u8]]) -> Builder {
    let mut b = Builder::new();
    b.feature |= crate::flags::FEATURE_CASEFOLD;
    b.s_encoding = crate::uapi::ENC_UTF8_12_1;
    let cf = crate::casefold::Casefold::load(crate::uapi::ENC_UTF8_12_1, 0).unwrap();
    let facts = crate::crypto::InodeFacts {
        is_dir: true, is_reg: false, is_symlink: false, casefolded: true,
    };
    let fs = crate::crypto::FsFacts { max_file_bytes: 1 << 42, blkbits: BLKSIZE_BITS as u8 };
    let info = crate::crypto::Info::setup(
        &Context { policy: policy(), nonce: nonce() },
        &facts, &fs, &MasterKey::new(&master_bytes()).unwrap(), &[0u8; 16], ROOT_INO).unwrap();
    assert!(info.has_dirhash_key(), "a folding encrypted directory must derive one");
    let mut s = nodes::Spec::dir(ROOT_INO);
    s.flags |= F2FS_ENCRYPT_FL | crate::flags::F2FS_CASEFOLD_FL;
    s.inline |= INLINE_DENTRY | INLINE_DATA | DATA_EXIST;
    s.xattr_nid = 100;
    let (at, len) = nodes::inline_span(&s);
    let layout = crate::dirent::Layout::inline(len);
    let mut all = nodes::dots(ROOT_INO, ROOT_INO);
    // The stored hash is over the FOLDED PLAINTEXT under the derived key — the
    // ciphertext differs per spelling and cannot be hashed. The map is keyed
    // by the stored bytes, which is all the area builder is handed.
    let mut by_stored: alloc::collections::BTreeMap<Vec<u8>, u32> =
        alloc::collections::BTreeMap::new();
    for (i, n) in names.iter().enumerate() {
        let stored = info.encrypt_name(n).unwrap();
        let q = crate::casefold::Query::prepare(&cf, n).unwrap();
        let folded = if q.kind() == crate::casefold::Fold::Folded { q.folded() } else { n };
        by_stored.insert(stored.clone(), info.dirhash(folded).unwrap());
        all.push(nodes::Ent { name: stored, ino: 10 + i as u32, file_type: FT_REG_FILE });
    }
    let area = nodes::dir::dentry_area_hashed(&layout, &all, |stored| {
        by_stored.get(stored).copied().unwrap_or(0)
    });
    let mut block = nodes::inode_block(&s);
    block[at..at + len].copy_from_slice(&area);
    nodes::place_inode(&mut b, &s, block, 2);
    let (ctx, n) =
        crate::crypto::policy::serialize(&Context { policy: policy(), nonce: nonce() });
    nodes::add_xattr_block(&mut b, ROOT_INO, 100,
        &[(XATTR_INDEX_ENCRYPTION, Vec::from(XATTR_NAME), Vec::from(&ctx[..n]))]);
    b
}

/// The two features together: any spelling of the name resolves, which needs
/// the keyed hash to pick the bucket AND the stored ciphertext to be decrypted
/// before it is folded. Getting either wrong makes the entry unfindable with
/// no error anywhere.
#[test]
fn a_folding_encrypted_directory_resolves_every_spelling() {
    let mut v = folding_encrypted_root(&[b"README.txt"]).mount().unwrap();
    v.add_encryption_key(&master_bytes()).unwrap();
    let root = v.root().unwrap();
    assert!(root.encrypted() && root.casefolded());
    for spelling in [&b"README.txt"[..], &b"readme.txt"[..], &b"ReAdMe.TXT"[..]] {
        assert_eq!(v.lookup(&root, ROOT_INO, spelling).unwrap().ino, 10,
                   "spelling {spelling:?} did not resolve");
    }
    assert_eq!(v.lookup(&root, ROOT_INO, b"other.txt").err(), Some(Errno::Enoent));
    // The listing reports the plaintext as it was created, not a folded form.
    assert!(v.read_dir(&root, ROOT_INO).unwrap().iter().any(|e| e.name == b"README.txt"));
}

/// The bucket such a directory files under is the KEYED hash — not the
/// format's own hash of the folded plaintext, and not the hash of the stored
/// ciphertext. Both of those are what a lookup would compute if either half
/// of the rule were dropped.
#[test]
fn the_keyed_hash_is_neither_of_the_two_unkeyed_hashes() {
    let mut v = folding_encrypted_root(&[b"README.txt"]).mount().unwrap();
    v.add_encryption_key(&master_bytes()).unwrap();
    let root = v.root().unwrap();
    let info = v.crypt_require_key(&root, ROOT_INO).unwrap().unwrap();
    let cf = crate::casefold::Casefold::load(crate::uapi::ENC_UTF8_12_1, 0).unwrap();
    let q = crate::casefold::Query::prepare(&cf, b"README.txt").unwrap();
    let keyed = info.dirhash(q.folded()).unwrap();
    assert_ne!(keyed, q.hash(), "keyed hash collapsed to the format's own hash");
    let ct = info.encrypt_name(b"README.txt").unwrap();
    assert_ne!(keyed, crate::hash::name_hash(&ct), "keyed hash collapsed to the ciphertext hash");
    // And the writer files under the same value the reader searches by.
    assert_eq!(v.entry_hash_crypt(&root, Some(&info), b"readme.TXT").unwrap(), keyed);
}

/// Locked, the same directory falls back to matching ciphertext: there is no
/// key to derive a hash with and no plaintext to fold, so the record the
/// listing produced carries the stored hash instead.
#[test]
fn a_locked_folding_directory_still_lists_and_resolves() {
    let v = folding_encrypted_root(&[b"README.txt"]).mount().unwrap();
    let root = v.root().unwrap();
    let list = v.read_dir(&root, ROOT_INO).unwrap();
    let shown = list.iter().find(|e| e.name != b"." && e.name != b"..").unwrap().name.clone();
    assert_ne!(shown, b"README.txt");
    assert_eq!(v.lookup(&root, ROOT_INO, &shown).unwrap().ino, 10);
    // Folding is not attempted on a locked directory: a record is not a
    // spelling, so a differently-cased record is simply not this entry.
    assert_eq!(v.lookup(&root, ROOT_INO, b"readme.txt").err(), Some(Errno::Enoent));
}

/// The same directory, but big enough that its entries live in BLOCKS rather
/// than inside the inode.
///
/// This is what makes the bucket hash load-bearing: a one-area inline
/// directory is searched whole, so a lookup that computes the wrong hash still
/// finds the entry. Only a directory with buckets can tell the two apart, and
/// the keyed hash exists precisely to pick the bucket.
fn folding_encrypted_block_root(names: &[&[u8]]) -> Builder {
    let mut b = Builder::new();
    b.feature |= crate::flags::FEATURE_CASEFOLD;
    b.s_encoding = crate::uapi::ENC_UTF8_12_1;
    let cf = crate::casefold::Casefold::load(crate::uapi::ENC_UTF8_12_1, 0).unwrap();
    let facts = crate::crypto::InodeFacts {
        is_dir: true, is_reg: false, is_symlink: false, casefolded: true,
    };
    let fs = crate::crypto::FsFacts { max_file_bytes: 1 << 42, blkbits: BLKSIZE_BITS as u8 };
    let info = crate::crypto::Info::setup(
        &Context { policy: policy(), nonce: nonce() },
        &facts, &fs, &MasterKey::new(&master_bytes()).unwrap(), &[0u8; 16], ROOT_INO).unwrap();
    let mut s = nodes::Spec::dir(ROOT_INO);
    s.flags |= F2FS_ENCRYPT_FL | crate::flags::F2FS_CASEFOLD_FL;
    s.current_depth = 1;
    s.dir_level = 0;
    s.xattr_nid = 100;
    let layout = crate::dirent::Layout::block();
    // Every entry goes to the bucket its KEYED hash names, which is where a
    // correct lookup will go looking for it.
    let mut per_block: Vec<(u64, Vec<nodes::Ent>, Vec<u32>)> = Vec::new();
    let push = |per: &mut Vec<(u64, Vec<nodes::Ent>, Vec<u32>)>, e: nodes::Ent, h: u32| {
        let idx = crate::dirent::bucket::search_range(h, 0, 0).start;
        match per.iter_mut().find(|(i, _, _)| *i == idx) {
            Some((_, v, hs)) => { v.push(e); hs.push(h); }
            None => per.push((idx, alloc::vec![e], alloc::vec![h])),
        }
    };
    for e in nodes::dots(ROOT_INO, ROOT_INO) { push(&mut per_block, e, 0); }
    for (i, n) in names.iter().enumerate() {
        let stored = info.encrypt_name(n).unwrap();
        let q = crate::casefold::Query::prepare(&cf, n).unwrap();
        let folded = if q.kind() == crate::casefold::Fold::Folded { q.folded() } else { n };
        let h = info.dirhash(folded).unwrap();
        push(&mut per_block,
             nodes::Ent { name: stored, ino: 10 + i as u32, file_type: FT_REG_FILE }, h);
    }
    let highest = per_block.iter().map(|(i, _, _)| *i).max().unwrap_or(0);
    s.size = (highest + 1) * BLKSIZE as u64;
    let blocks: Vec<(u64, Vec<u8>)> = per_block
        .into_iter()
        .map(|(i, v, hs)| {
            // Keyed by the stored bytes, since that is all the area builder is
            // handed; the two exempt names hash to zero either way.
            let by_stored: alloc::collections::BTreeMap<Vec<u8>, u32> =
                v.iter().map(|e| e.name.clone()).zip(hs).collect();
            let area = nodes::dir::dentry_area_hashed(&layout, &v, |stored| {
                by_stored.get(stored).copied().unwrap_or(0)
            });
            (i, area)
        })
        .collect();
    nodes::add_sparse_with(&mut b, s, &blocks);
    let (ctx, n) =
        crate::crypto::policy::serialize(&Context { policy: policy(), nonce: nonce() });
    nodes::add_xattr_block(&mut b, ROOT_INO, 100,
        &[(XATTR_INDEX_ENCRYPTION, Vec::from(XATTR_NAME), Vec::from(&ctx[..n]))]);
    b
}

/// With buckets in play, the keyed hash is what finds the entry at all: a
/// lookup that hashed the folded plaintext with the format's own hash, or
/// hashed the ciphertext, would search a bucket the entry is not in and report
/// that the name does not exist.
#[test]
fn a_bucketed_folding_encrypted_directory_needs_the_keyed_hash_to_find_anything() {
    let mut v = folding_encrypted_block_root(&[b"README.txt"]).mount().unwrap();
    v.add_encryption_key(&master_bytes()).unwrap();
    let root = v.root().unwrap();
    assert!(!root.inline_dentry(), "the fixture must not be an inline directory");
    for spelling in [&b"README.txt"[..], &b"readme.txt"[..], &b"ReAdMe.TXT"[..]] {
        assert_eq!(v.lookup(&root, ROOT_INO, spelling).unwrap().ino, 10,
                   "spelling {spelling:?} did not resolve");
    }
    assert!(v.read_dir(&root, ROOT_INO).unwrap().iter().any(|e| e.name == b"README.txt"));
}

/// The same directory locked: the record a listing hands back carries the
/// stored keyed hash, which is the only way a keyless lookup can reach the
/// bucket at all.
#[test]
fn a_locked_bucketed_directory_finds_its_entry_by_the_hash_in_the_record() {
    let v = folding_encrypted_block_root(&[b"README.txt"]).mount().unwrap();
    let root = v.root().unwrap();
    let list = v.read_dir(&root, ROOT_INO).unwrap();
    let shown = list.iter().find(|e| e.name != b"." && e.name != b"..").unwrap().name.clone();
    assert_eq!(v.lookup(&root, ROOT_INO, &shown).unwrap().ino, 10);
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
