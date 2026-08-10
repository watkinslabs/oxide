use super::Fdt;
use crate::header::*;

/// Header prefix of a legal blob, with individual fields overridable.
fn hdr(magic: u32, totalsize: u32, version: u32, last_comp: u32) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; 64];
    v[0..4].copy_from_slice(&magic.to_be_bytes());
    v[4..8].copy_from_slice(&totalsize.to_be_bytes());
    v[8..12].copy_from_slice(&40u32.to_be_bytes());
    v[12..16].copy_from_slice(&48u32.to_be_bytes());
    v[16..20].copy_from_slice(&40u32.to_be_bytes());
    v[20..24].copy_from_slice(&version.to_be_bytes());
    v[24..28].copy_from_slice(&last_comp.to_be_bytes());
    v[28..32].copy_from_slice(&0u32.to_be_bytes());
    v[32..36].copy_from_slice(&8u32.to_be_bytes());
    v[36..40].copy_from_slice(&8u32.to_be_bytes());
    v
}

#[test]
fn rejects_truncated() {
    let buf = alloc::vec![0u8; 16];
    assert_eq!(parse_header(&buf).err(), Some(DtbError::Truncated));
}

#[test]
fn rejects_bad_magic() {
    let buf = hdr(0xdead_beef, 64, 17, FDT_LAST_COMPAT_VERSION);
    assert_eq!(parse_header(&buf).err(), Some(DtbError::BadMagic));
}

#[test]
fn accepts_known_version() {
    let buf = hdr(FDT_MAGIC, 64, 17, FDT_LAST_COMPAT_VERSION);
    let h = parse_header(&buf).unwrap();
    assert_eq!(h.magic, FDT_MAGIC);
    assert_eq!(h.totalsize, 64);
    assert_eq!(h.last_comp_version, FDT_LAST_COMPAT_VERSION);
}

#[test]
fn rejects_future_compat_version() {
    let buf = hdr(FDT_MAGIC, 64, 99, FDT_LAST_COMPAT_VERSION + 1);
    assert_eq!(parse_header(&buf).err(), Some(DtbError::UnsupportedVersion));
}

#[test]
fn rejects_totalsize_exceeding_buffer() {
    let mut buf = hdr(FDT_MAGIC, 1024, 17, FDT_LAST_COMPAT_VERSION);
    buf.truncate(64);
    assert_eq!(parse_header(&buf).err(), Some(DtbError::Truncated));
}

#[test]
fn fdt_magic_is_big_endian_d00dfeed() {
    // Bootloaders write the magic in big-endian wire order; we read with
    // `from_be_bytes`.
    assert_eq!(FDT_MAGIC, 0xd00d_feed);
}

/// The boot path learns how much to map from an 8-byte prefix, which
/// `parse_header` structurally cannot serve (its `totalsize <= len` check
/// rejects any prefix). This is the contract that lets the DTB be bounded
/// before it is mapped.
#[test]
fn totalsize_from_prefix_reads_an_eight_byte_head() {
    let blob = Fdt::new().begin("").end().finish();
    let ts = parse_header(&blob).unwrap().totalsize as usize;
    assert_eq!(totalsize_from_prefix(&blob[..8]), Some(ts));
    assert_eq!(ts, blob.len());
    assert!(parse_header(&blob[..8]).is_err(), "prefix must not satisfy the full parse");
}

#[test]
fn totalsize_from_prefix_rejects_bad_magic_short_and_oversize() {
    let mut p = [0u8; 8];
    p[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
    p[4..8].copy_from_slice(&(FDT_HEADER_LEN as u32).to_be_bytes());
    assert_eq!(totalsize_from_prefix(&p), Some(FDT_HEADER_LEN));
    assert_eq!(totalsize_from_prefix(&p[..7]), None, "short prefix");
    let mut bad = p;
    bad[0] = 0;
    assert_eq!(totalsize_from_prefix(&bad), None, "bad magic");
    let mut small = p;
    small[4..8].copy_from_slice(&8u32.to_be_bytes());
    assert_eq!(totalsize_from_prefix(&small), None, "smaller than a header");
    let mut huge = p;
    huge[4..8].copy_from_slice(&((FDT_MAX_TOTALSIZE + 1) as u32).to_be_bytes());
    assert_eq!(totalsize_from_prefix(&huge), None, "beyond the accepted ceiling");
}

/// A reservation-block offset inside the header describes a block overlapping
/// the header itself. Accepting it lets a blob through that every strict
/// reader refuses, which is worse than refusing it here.
#[test]
fn rejects_a_reservation_block_overlapping_the_header() {
    for off in [0u32, 8, 39] {
        let mut buf = hdr(FDT_MAGIC, 64, 17, FDT_LAST_COMPAT_VERSION);
        buf[16..20].copy_from_slice(&off.to_be_bytes());
        assert_eq!(parse_header(&buf).err(), Some(DtbError::Inval), "off {off}");
    }
    let mut ok = hdr(FDT_MAGIC, 64, 17, FDT_LAST_COMPAT_VERSION);
    ok[16..20].copy_from_slice(&(FDT_HEADER_LEN as u32).to_be_bytes());
    assert!(parse_header(&ok).is_ok());
}
