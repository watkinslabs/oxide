use super::*;


const ISIZE: usize = 256;
const HDR: usize = 160; // 128 + 32

fn blank_inode() -> Vec<u8> {
    let mut b = alloc::vec![0u8; ISIZE];
    b[0x80..0x82].copy_from_slice(&32u16.to_le_bytes()); // i_extra_isize
    b
}

#[test]
fn name_split_join_roundtrip() {
    for full in ["user.foo", "trusted.x", "security.selinux", "system.bar",
                 "system.posix_acl_access", "system.posix_acl_default"] {
        let (idx, suffix) = split_name(full).expect("split");
        assert_eq!(join_name(idx, suffix).as_deref(), Some(full));
    }
    assert!(split_name("bogus.ns").is_none());
}

#[test]
fn ibody_encode_decode_roundtrip() {
    let mut b = blank_inode();
    let entries = alloc::vec![
        ("security.selinux".to_string(), b"system_u:object_r:etc_t:s0\0".to_vec()),
        ("user.comment".to_string(), b"hello".to_vec()),
    ];
    encode_ibody(&mut b, HDR, ISIZE, &entries).expect("encode");
    // magic present
    assert_eq!(u32::from_le_bytes([b[HDR], b[HDR+1], b[HDR+2], b[HDR+3]]), EXT4_XATTR_MAGIC);
    let mut got = decode_ibody(&b, HDR, ISIZE);
    got.sort();
    let mut want = entries.clone();
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn ibody_xattr_name_preserves_non_utf8_suffix_bytes() {
    let mut b = blank_inode();
    let raw_suffix = b"raw-\xff";
    let mut full = "user.".to_string();
    full.push_str(&vfs::path_from_bytes(raw_suffix));
    let entries = alloc::vec![(full.clone(), b"v".to_vec())];
    encode_ibody(&mut b, HDR, ISIZE, &entries).expect("encode raw suffix");
    let name_start = HDR + 4 + ENTRY_HDR_LEN;
    assert_eq!(b[HDR + 4] as usize, raw_suffix.len());
    assert_eq!(&b[name_start..name_start + raw_suffix.len()], raw_suffix);
    assert_eq!(decode_ibody(&b, HDR, ISIZE), entries);
}

#[test]
fn empty_entries_leaves_no_magic() {
    let mut b = blank_inode();
    encode_ibody(&mut b, HDR, ISIZE, &[]).expect("encode empty");
    // region is all-zero → no magic → decode empty
    assert!(decode_ibody(&b, HDR, ISIZE).is_empty());
    for &byte in &b[HDR..ISIZE] { assert_eq!(byte, 0); }
}

#[test]
fn overflow_returns_err() {
    let mut b = blank_inode();
    // 96-byte ibody region (160..256) cannot hold a 200-byte value.
    let entries = alloc::vec![("user.big".to_string(), alloc::vec![0xABu8; 200])];
    assert!(encode_ibody(&mut b, HDR, ISIZE, &entries).is_err());
}

#[test]
fn posix_acl_zero_name_len() {
    let mut b = blank_inode();
    let entries = alloc::vec![("system.posix_acl_access".to_string(), b"\x02\x00\x00\x00".to_vec())];
    encode_ibody(&mut b, HDR, ISIZE, &entries).expect("encode acl");
    // entry name_len must be 0, name_index 2
    assert_eq!(b[HDR + 4], 0, "posix_acl entry has zero-length name");
    assert_eq!(b[HDR + 5], 2, "posix_acl_access name_index = 2");
    let got = decode_ibody(&b, HDR, ISIZE);
    assert_eq!(got, entries);
}

#[test]
fn external_block_decode() {
    let bs = 1024usize;
    let mut blk = alloc::vec![0u8; bs];
    blk[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    // one entry: user.x = "v", value at end of block.
    let name = b"x";
    let p = BLOCK_HDR_LEN;
    blk[p] = name.len() as u8;       // name_len
    blk[p + 1] = 1;                  // name_index = user
    let value_pos = bs - 4;          // aligned slot
    blk[p + 2..p + 4].copy_from_slice(&(value_pos as u16).to_le_bytes()); // value_offs (base = block start)
    blk[p + 8..p + 12].copy_from_slice(&1u32.to_le_bytes());              // value_size
    blk[p + ENTRY_HDR_LEN..p + ENTRY_HDR_LEN + 1].copy_from_slice(name);
    blk[value_pos] = b'v';
    let got = decode_block(&blk);
    assert_eq!(got, alloc::vec![("user.x".to_string(), b"v".to_vec())]);
}

#[test]
fn external_xattr_name_preserves_non_utf8_suffix_bytes() {
    let raw_suffix = b"raw-\xff";
    let mut full = "user.".to_string();
    full.push_str(&vfs::path_from_bytes(raw_suffix));
    let entries = alloc::vec![(full.clone(), b"v".to_vec())];
    let blk = encode_block(&entries, 1024).expect("encode external raw suffix");
    let name_start = BLOCK_HDR_LEN + ENTRY_HDR_LEN;
    assert_eq!(blk[BLOCK_HDR_LEN] as usize, raw_suffix.len());
    assert_eq!(&blk[name_start..name_start + raw_suffix.len()], raw_suffix);
    assert_eq!(decode_block(&blk), entries);
}
