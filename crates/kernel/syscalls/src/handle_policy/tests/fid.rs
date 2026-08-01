use crate::handle_policy::decode::{FILEID_IS_CONNECTABLE, FILEID_IS_DIR, header_is_our_fid,
    strip_user_flags};
use crate::handle_policy::fid::*;
use syscall::errno::Errno;

fn roundtrip(fid: Fid) -> (Fid, u32, i32) {
    let mut buf = [0u8; FID_LEN_PARENT as usize];
    let (len, htype) = encode_fid(&fid, &mut buf);
    let back = decode_fid(&buf[..len as usize], htype).expect("decodes");
    (back, len, htype)
}

/// The identity FID round-trips BOTH halves. A codec that dropped the
/// generation would compile, pass an ino-only test, and silently reopen a
/// recycled inode — so the generation is asserted explicitly. # C: O(1)
#[test]
fn identity_fid_round_trips_ino_and_generation() {
    for (ino, generation) in [(1u64, 1u32), (2, 0xDEAD_BEEF), (u64::MAX, u32::MAX),
                              (0xFFFF_0000_0000_0002, 7)] {
        let (back, len, htype) = roundtrip(Fid { ino, generation, parent: None });
        assert_eq!(back, Fid { ino, generation, parent: None });
        assert_eq!(len, FID_LEN);
        assert_eq!(htype, HANDLE_TYPE_INO_GEN);
    }
}

/// A 64-bit inode number survives encode. This kernel tags a backend's inodes
/// in the HIGH 32 bits, so a Linux-shaped 32-bit `ino` field would collapse
/// every tagged inode onto its untagged twin — the handle would resolve to a
/// different file on a different filesystem. # C: O(1)
#[test]
fn high_half_of_the_inode_number_survives() {
    let tagged = 0xFFFF_0000_0000_000Cu64;
    let (back, _, _) = roundtrip(Fid { ino: tagged, generation: 3, parent: None });
    assert_eq!(back.ino, tagged);
    assert_ne!(back.ino, tagged & 0xFFFF_FFFF, "the tag must not be truncated away");
}

/// The connectable FID carries the parent identity and decodes to a DIFFERENT
/// handle_type, so a decoder can tell the two apart without out-of-band state.
/// # C: O(1)
#[test]
fn connectable_fid_round_trips_the_parent() {
    let fid = Fid { ino: 42, generation: 9, parent: Some((7, 0xABCD)) };
    let (back, len, htype) = roundtrip(fid);
    assert_eq!(back, fid);
    assert_eq!(back.parent, Some((7, 0xABCD)));
    assert_eq!(len, FID_LEN_PARENT);
    assert_eq!(htype, HANDLE_TYPE_INO_GEN_PARENT);
    assert_ne!(HANDLE_TYPE_INO_GEN, HANDLE_TYPE_INO_GEN_PARENT);
}

/// A connectable request sizes the handle by what the object actually needs: a
/// directory encodes no parent (one dentry, reconnected through `..`), a
/// non-directory does. # C: O(1)
#[test]
fn connectable_length_depends_on_directoryness() {
    assert_eq!(encoded_fid_len(false, false), FID_LEN);
    assert_eq!(encoded_fid_len(false, true),  FID_LEN);
    assert_eq!(encoded_fid_len(true,  true),  FID_LEN);
    assert_eq!(encoded_fid_len(true,  false), FID_LEN_PARENT);
    assert!(FID_LEN_PARENT > FID_LEN);
}

/// A type this kernel never encoded, and a payload whose length disagrees with
/// its type, are both ESTALE — never EINVAL, and never a decode against
/// whatever bytes happened to be there. # C: O(1)
#[test]
fn foreign_and_truncated_handles_are_stale() {
    assert_eq!(decode_fid(&[0u8; 12], 3), Err(Errno::Estale), "unknown handle_type");
    assert_eq!(decode_fid(&[0u8; 12], 0), Err(Errno::Estale), "type 0 is the fs root, not a FID");
    assert_eq!(decode_fid(&[0u8; 8], HANDLE_TYPE_INO_GEN), Err(Errno::Estale), "short payload");
    assert_eq!(decode_fid(&[0u8; 12], HANDLE_TYPE_INO_GEN_PARENT), Err(Errno::Estale),
        "connectable type with a plain-length payload");
    assert_eq!(decode_fid(&[0u8; 24], HANDLE_TYPE_INO_GEN), Err(Errno::Estale), "over-long payload");
    assert_eq!(fid_len_for_type(HANDLE_TYPE_INO_GEN), Some(FID_LEN));
    assert_eq!(fid_len_for_type(HANDLE_TYPE_INO_GEN_PARENT), Some(FID_LEN_PARENT));
    assert_eq!(fid_len_for_type(99), None);
}

/// The user-flag bits ride in `handle_type` alongside the FID type; stripping
/// them must leave the type intact, and classification must still recognise
/// the handle. A decoder that forgot to strip would see type `0x10001` and
/// report ESTALE for every connectable handle it had itself minted. # C: O(1)
#[test]
fn user_flags_do_not_hide_the_fid_type() {
    for f in [FILEID_IS_CONNECTABLE, FILEID_IS_DIR, FILEID_IS_CONNECTABLE | FILEID_IS_DIR] {
        assert_eq!(strip_user_flags(HANDLE_TYPE_INO_GEN | f), HANDLE_TYPE_INO_GEN);
        assert!(header_is_our_fid(FID_LEN, HANDLE_TYPE_INO_GEN | f), "flag {f:#x}");
        assert!(header_is_our_fid(FID_LEN_PARENT, HANDLE_TYPE_INO_GEN_PARENT | f), "flag {f:#x}");
        let mut buf = [0u8; FID_LEN_PARENT as usize];
        let (len, _) = encode_fid(&Fid { ino: 5, generation: 6, parent: None }, &mut buf);
        assert!(decode_fid(&buf[..len as usize], strip_user_flags(HANDLE_TYPE_INO_GEN | f)).is_ok());
    }
}

/// Classification rejects a length that does not match the claimed type, so a
/// caller cannot present a 12-byte payload as a connectable handle and have
/// the parent read out of adjacent bytes. # C: O(1)
#[test]
fn classification_requires_the_length_the_type_claims() {
    assert!(!header_is_our_fid(FID_LEN, HANDLE_TYPE_INO_GEN_PARENT));
    assert!(!header_is_our_fid(FID_LEN_PARENT, HANDLE_TYPE_INO_GEN));
    assert!(!header_is_our_fid(8, HANDLE_TYPE_INO_GEN), "the pre-generation 8-byte FID is not ours");
    assert!(!header_is_our_fid(FID_LEN, 0), "type 0 is the filesystem root, not an inode FID");
}
