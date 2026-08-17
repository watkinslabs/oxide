//! The name a locked directory shows: its encoding, its round trip, and the
//! matching that finds the entry again.

use alloc::vec::Vec;

use super::fixture::*;
use crate::crypto::uapi::*;
use crate::crypto::{base64, name, nokey, FscryptError};

/// The exact record a locked listing prints for a known ciphertext and hash.
#[test]
fn a_short_ciphertext_encodes_to_its_known_record() {
    let ct = hexv("c1818e1645b4e4057caebf945f07bb45");
    let shown = nokey::present(0xdead_beef, 0, &ct).unwrap();
    assert_eq!(shown, b"776t3gAAAADBgY4WRbTkBXyuv5RfB7tF");
    let back = nokey::parse(&shown).unwrap();
    assert_eq!(back.hash, 0xdead_beef);
    assert_eq!(back.minor_hash, 0);
    assert_eq!(back.disk_name(), Some(&ct[..]));
}

/// A ciphertext longer than the record's field is abbreviated by a digest of
/// its tail, so the presented name still fits a directory entry.
#[test]
fn a_long_ciphertext_is_abbreviated_by_a_digest_of_its_tail() {
    let ct: Vec<u8> = (0..160usize).map(|i| ((i * 7 + 1) & 0xff) as u8).collect();
    let shown = nokey::present(1, 0, &ct).unwrap();
    assert_eq!(shown.len(), NOKEY_NAME_MAX_ENCODED);
    assert!(shown.len() <= crate::uapi::NAME_LEN);
    let back = nokey::parse(&shown).unwrap();
    assert_eq!(back.hash, 1);
    // The whole ciphertext is not recoverable, so the record matches instead.
    assert_eq!(back.disk_name(), None);
    assert!(back.matches(&ct));
    // A name sharing the first 149 bytes but differing after is a different
    // entry, which the digest is what distinguishes.
    let mut other = ct.clone();
    let last = other.len() - 1;
    other[last] ^= 1;
    assert!(!back.matches(&other));
    // And a name that is merely the prefix does not match either.
    assert!(!back.matches(&ct[..NOKEY_BYTES]));
}

/// The boundary: exactly the field width is carried whole, one byte more is
/// abbreviated.
#[test]
fn the_abbreviation_boundary_is_the_field_width() {
    let exact: Vec<u8> = (0..NOKEY_BYTES).map(|i| i as u8).collect();
    let r = nokey::parse(&nokey::present(7, 0, &exact).unwrap()).unwrap();
    assert_eq!(r.disk_name(), Some(&exact[..]));
    let over: Vec<u8> = (0..NOKEY_BYTES + 1).map(|i| i as u8).collect();
    let r2 = nokey::parse(&nokey::present(7, 0, &over).unwrap()).unwrap();
    assert_eq!(r2.disk_name(), None);
    assert!(r2.matches(&over));
}

/// Every ciphertext length round-trips through the presentation, which is
/// what makes a listed name usable for a later lookup or unlink.
#[test]
fn every_ciphertext_length_round_trips() {
    for n in FNAME_MIN_MSG_LEN..=crate::uapi::NAME_LEN {
        let ct: Vec<u8> = (0..n).map(|i| (i * 3 + 1) as u8).collect();
        let shown = nokey::present(0x1234_5678, 0, &ct).unwrap();
        assert!(shown.len() <= crate::uapi::NAME_LEN, "presented name too long at {n}");
        let back = nokey::parse(&shown).unwrap();
        assert_eq!(back.hash, 0x1234_5678);
        assert!(back.matches(&ct), "length {n} does not match itself");
    }
}

/// A ciphertext shorter than the minimum message length did not come from
/// this construction, so the directory is damaged rather than merely locked.
#[test]
fn a_ciphertext_below_the_minimum_is_corrupt() {
    assert_eq!(nokey::present(0, 0, &[0u8; 15]).unwrap_err(), FscryptError::CorruptName);
}

/// The two exempt names pass through: a locked directory still lists them.
#[test]
fn dot_and_dotdot_are_shown_as_themselves() {
    assert_eq!(nokey::present(0, 0, b".").unwrap(), b".");
    assert_eq!(nokey::present(0, 0, b"..").unwrap(), b"..");
}

/// A name that is not a well-formed record names no entry — which is
/// `ENOENT`, not an error about the directory.
#[test]
fn a_malformed_presented_name_names_no_entry() {
    for bad in [&b""[..], &b"A"[..], &b"AAAAAAAAAAA"[..], &b"not+base64url/"[..]] {
        let e = nokey::parse(bad).unwrap_err();
        assert_eq!(e, FscryptError::NoSuchName);
        assert_eq!(e.errno(), syscall::errno::Errno::Enoent);
    }
    // Longer than any record can encode to.
    let long = alloc::vec![b'A'; NOKEY_NAME_MAX_ENCODED + 1];
    assert_eq!(nokey::parse(&long).unwrap_err(), FscryptError::NoSuchName);
}

/// A decoded length between the ciphertext field and the full record is not a
/// record: the digest is present or absent whole.
#[test]
fn a_partial_digest_is_not_a_record() {
    let mut rec = [0u8; NOKEY_NAME_MAX];
    for (i, b) in rec.iter_mut().enumerate() { *b = i as u8; }
    // One byte past the ciphertext field: a truncated digest.
    let size = NOKEY_DIRHASH + NOKEY_BYTES + 1;
    let mut enc = alloc::vec![0u8; base64::encoded_len(size)];
    let n = base64::encode(&rec[..size], &mut enc);
    enc.truncate(n);
    assert_eq!(nokey::parse(&enc).unwrap_err(), FscryptError::NoSuchName);
}

/// The encoding is URL-safe and unpadded, and the spare bits of a short final
/// group must be zero — otherwise one entry would answer to two names.
#[test]
fn the_encoding_is_canonical() {
    let mut out = [0u8; 8];
    let n = base64::encode(b"\xff\xff\xff", &mut out);
    assert_eq!(&out[..n], b"____");
    let n = base64::encode(b"\xfb\xff", &mut out);
    assert_eq!(&out[..n], b"-_8");
    let mut back = [0u8; 8];
    assert_eq!(base64::decode(b"-_8", &mut back), Some(2));
    assert_eq!(&back[..2], b"\xfb\xff");
    // "-_9" decodes the same two bytes with a spare bit set, and is refused.
    assert_eq!(base64::decode(b"-_9", &mut back), None);
    // A lone trailing character encodes nothing.
    assert_eq!(base64::decode(b"AAAAA", &mut back), None);
    // The standard alphabet's characters are not in this one.
    assert_eq!(base64::decode(b"+/==", &mut back), None);
}

#[test]
fn every_byte_string_round_trips_through_the_encoding() {
    for n in 0..40usize {
        let src: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
        let mut enc = alloc::vec![0u8; base64::encoded_len(n)];
        let w = base64::encode(&src, &mut enc);
        assert_eq!(w, base64::encoded_len(n));
        let mut back = alloc::vec![0u8; n + 3];
        assert_eq!(base64::decode(&enc[..w], &mut back), Some(n));
        assert_eq!(&back[..n], &src[..]);
    }
}

/// Without the key, creating an entry is impossible: there is no plaintext to
/// encrypt, so it is `ENOKEY` rather than a name made of the supplied bytes.
#[test]
fn a_keyless_directory_permits_lookup_and_refuses_creation() {
    let shown = nokey::present(5, 0, &hexv("c1818e1645b4e4057caebf945f07bb45")).unwrap();
    let s = name::setup(None, &shown, true).unwrap();
    assert_eq!(s.hash(), Some(5));
    let e = name::setup(None, &shown, false).err().expect("creation needs the key");
    assert_eq!(e, FscryptError::NoKey);
    assert_eq!(e.errno(), syscall::errno::Errno::Enokey);
}

/// With the key, a search compares ciphertext and the hash comes from the
/// stored bytes as usual.
#[test]
fn a_keyed_directory_searches_by_ciphertext() {
    let d = info(dir(), 9);
    let s = name::setup(Some(&d), b"hello", true).unwrap();
    assert_eq!(s.disk_name(), Some(&hexv("c1818e1645b4e4057caebf945f07bb45")[..]));
    assert_eq!(s.hash(), None);
    assert!(s.matches(&hexv("c1818e1645b4e4057caebf945f07bb45")));
    assert!(!s.matches(b"something else entirely"));
}

/// The two exempt names are searched for as themselves whatever the state of
/// the key.
#[test]
fn the_exempt_names_search_as_themselves() {
    let d = info(dir(), 9);
    for n in [&b"."[..], &b".."[..]] {
        assert_eq!(name::setup(Some(&d), n, true).unwrap().disk_name(), Some(n));
        assert_eq!(name::setup(None, n, true).unwrap().disk_name(), Some(n));
        assert_eq!(name::setup(None, n, false).unwrap().disk_name(), Some(n));
    }
}

/// What a listing shows is a name a later lookup accepts — with the key it is
/// the plaintext, without it the record, and both find the same entry.
#[test]
fn a_listed_name_is_a_name_a_lookup_accepts() {
    let d = info(dir(), 9);
    let ct = d.encrypt_name(b"quarterly-report.pdf").unwrap();
    let hash = crate::hash::name_hash(&ct);
    let with = name::present(Some(&d), hash, &ct).unwrap();
    assert_eq!(with, b"quarterly-report.pdf");
    assert!(name::setup(Some(&d), &with, true).unwrap().matches(&ct));
    let without = name::present(None, hash, &ct).unwrap();
    let s = name::setup(None, &without, true).unwrap();
    assert_eq!(s.hash(), Some(hash));
    assert!(s.matches(&ct));
}
