// RPM v3 / v4 package format reader (no signature verification, no
// cpio extraction in v1 — those land in P16-02 / P16-03).
//
// On-disk layout:
//   [Lead   ] 96 bytes — magic 0xed,0xab,0xee,0xdb + version + type + ...
//   [Sig hdr] aligned-to-8 (skipped here; signature verify is P16-04)
//   [Pkg hdr] header section: 16-byte hdr + index entries + store
//   [Payload] cpio.gz / cpio.xz / cpio.zstd (parsed by separate crate)
//
// Headers (both signature and package) share the same layout:
//   8 bytes magic+version+reserved (8e ad e8 01 00 00 00 00)
//   4 bytes BE entry count
//   4 bytes BE store size
//   N × 16-byte index entries: {tag:BE32, type:BE32, off:BE32, count:BE32}
//   <store: blob of strings/ints addressed by index entries>
//
// We expose:
//   parse(bytes) -> Result<Package>
//   Package::tag_str(tag) -> Option<&str>
//   Package::tag_u32(tag) -> Option<u32>

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;
use alloc::vec::Vec;

pub const LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
pub const HDR_MAGIC:  [u8; 3] = [0x8e, 0xad, 0xe8];

pub const RPMTAG_NAME:        u32 = 1000;
pub const RPMTAG_VERSION:     u32 = 1001;
pub const RPMTAG_RELEASE:     u32 = 1002;
pub const RPMTAG_SUMMARY:     u32 = 1004;
pub const RPMTAG_DESCRIPTION: u32 = 1005;
pub const RPMTAG_BUILDTIME:   u32 = 1006;
pub const RPMTAG_LICENSE:     u32 = 1014;
pub const RPMTAG_GROUP:       u32 = 1016;
pub const RPMTAG_ARCH:        u32 = 1022;
pub const RPMTAG_FILESIZES:   u32 = 1028;
pub const RPMTAG_SIZE:        u32 = 1009;
pub const RPMTAG_PAYLOADFORMAT:    u32 = 1124;
pub const RPMTAG_PAYLOADCOMPRESSOR:u32 = 1125;
pub const RPMTAG_BASENAMES:   u32 = 1117;
pub const RPMTAG_DIRNAMES:    u32 = 1118;
pub const RPMTAG_DIRINDEXES:  u32 = 1116;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TagType {
    Null      = 0,
    Char      = 1,
    Int8      = 2,
    Int16     = 3,
    Int32     = 4,
    Int64     = 5,
    String    = 6,
    Bin       = 7,
    StringArr = 8,
    I18nStr   = 9,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    BadLead,
    BadSigHeader,
    BadPkgHeader,
    Truncated,
    UnknownTagType,
}

#[derive(Clone, Debug)]
pub struct IndexEntry {
    pub tag:    u32,
    pub kind:   u32,
    pub off:    u32,
    pub count:  u32,
}

#[derive(Clone, Debug)]
pub struct Package<'a> {
    pub entries: Vec<IndexEntry>,
    pub store:   &'a [u8],
    pub payload_off: usize,
}

#[inline] fn rd_be32(b: &[u8]) -> u32 {
    ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | (b[3] as u32)
}

fn parse_header(buf: &[u8]) -> Result<(Vec<IndexEntry>, usize, usize), Error> {
    if buf.len() < 16 { return Err(Error::Truncated); }
    if buf[0..3] != HDR_MAGIC { return Err(Error::BadPkgHeader); }
    let count   = rd_be32(&buf[8..12]) as usize;
    let store_n = rd_be32(&buf[12..16]) as usize;
    let idx_off = 16;
    let store_off = idx_off + count * 16;
    let total = store_off + store_n;
    if buf.len() < total { return Err(Error::Truncated); }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let p = idx_off + i * 16;
        out.push(IndexEntry {
            tag:   rd_be32(&buf[p..p+4]),
            kind:  rd_be32(&buf[p+4..p+8]),
            off:   rd_be32(&buf[p+8..p+12]),
            count: rd_be32(&buf[p+12..p+16]),
        });
    }
    Ok((out, store_off, total))
}

/// Parse an RPM file. Skips the signature header without verifying it.
/// # C: O(N + count)
pub fn parse(buf: &[u8]) -> Result<Package<'_>, Error> {
    if buf.len() < 96 { return Err(Error::Truncated); }
    if buf[0..4] != LEAD_MAGIC { return Err(Error::BadLead); }
    let mut off = 96;

    // Signature header (always present in v3/v4). Aligned to 8 bytes after.
    let (_, _, sig_total) = parse_header(&buf[off..]).map_err(|e| match e {
        Error::BadPkgHeader => Error::BadSigHeader,
        x => x,
    })?;
    off += sig_total;
    // Pad to 8-byte boundary.
    off = (off + 7) & !7;

    // Package header.
    let (entries, store_off_in_hdr, pkg_total) = parse_header(&buf[off..])?;
    let abs_store_off = off + store_off_in_hdr;
    let abs_store_end = off + pkg_total;
    let store = &buf[abs_store_off..abs_store_end];
    let payload_off = abs_store_end;

    Ok(Package { entries, store, payload_off })
}

impl<'a> Package<'a> {
    pub fn find(&self, tag: u32) -> Option<&IndexEntry> {
        self.entries.iter().find(|e| e.tag == tag)
    }

    /// Read a NUL-terminated string out of the store. Returns None
    /// if the entry isn't found, isn't a String/I18nStr, or runs
    /// past the store.
    pub fn tag_str(&self, tag: u32) -> Option<&str> {
        let e = self.find(tag)?;
        if e.kind != TagType::String as u32 && e.kind != TagType::I18nStr as u32 {
            return None;
        }
        let start = e.off as usize;
        if start >= self.store.len() { return None; }
        let end = self.store[start..].iter().position(|&b| b == 0).map(|i| start + i)?;
        core::str::from_utf8(&self.store[start..end]).ok()
    }

    pub fn tag_u32(&self, tag: u32) -> Option<u32> {
        let e = self.find(tag)?;
        if e.kind != TagType::Int32 as u32 { return None; }
        let p = e.off as usize;
        if p + 4 > self.store.len() { return None; }
        Some(rd_be32(&self.store[p..p+4]))
    }

    /// Returns each string in a StringArr entry. Allocates Vec.
    pub fn tag_string_array(&self, tag: u32) -> Option<Vec<&str>> {
        let e = self.find(tag)?;
        if e.kind != TagType::StringArr as u32 && e.kind != TagType::I18nStr as u32 {
            return None;
        }
        let mut out = Vec::with_capacity(e.count as usize);
        let mut p = e.off as usize;
        for _ in 0..e.count {
            if p >= self.store.len() { return None; }
            let end = self.store[p..].iter().position(|&b| b == 0).map(|i| p + i)?;
            out.push(core::str::from_utf8(&self.store[p..end]).ok()?);
            p = end + 1;
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal RPM-shape blob: lead + sig-hdr (1 entry) +
    /// pkg-hdr (NAME, VERSION, ARCH). Used to validate parse paths.
    fn make_rpm() -> Vec<u8> {
        let mut out = Vec::new();
        // Lead: 96 bytes, magic + zeros.
        out.extend_from_slice(&[0xed,0xab,0xee,0xdb]);
        out.resize(96, 0);

        // Signature header: empty (count=0, store=0).
        out.extend_from_slice(&[0x8e,0xad,0xe8,0x01, 0,0,0,0]); // magic+ver+reserved
        out.extend_from_slice(&[0,0,0,0]); // count
        out.extend_from_slice(&[0,0,0,0]); // store size
        // Pad to 8.
        while out.len() % 8 != 0 { out.push(0); }

        // Package header.
        let pkg_hdr_start = out.len();
        out.extend_from_slice(&[0x8e,0xad,0xe8,0x01, 0,0,0,0]);
        let count_off = out.len();
        out.extend_from_slice(&[0,0,0,0]);
        let store_off = out.len();
        out.extend_from_slice(&[0,0,0,0]);

        // 3 index entries: NAME (1000, str, off=0), VERSION (1001, str, off=5), ARCH (1022, str, off=11)
        let mk = |tag: u32, kind: u32, off: u32, n: u32, dst: &mut Vec<u8>| {
            dst.extend_from_slice(&tag.to_be_bytes());
            dst.extend_from_slice(&kind.to_be_bytes());
            dst.extend_from_slice(&off.to_be_bytes());
            dst.extend_from_slice(&n.to_be_bytes());
        };
        mk(RPMTAG_NAME,    TagType::String as u32, 0,  1, &mut out);
        mk(RPMTAG_VERSION, TagType::String as u32, 5,  1, &mut out);
        mk(RPMTAG_ARCH,    TagType::String as u32, 9,  1, &mut out);
        // 3 entries → 48 bytes.

        // Store: "test\0" "1.0\0" "x86_64\0"
        let store = b"test\01.0\0x86_64\0";
        out.extend_from_slice(store);

        // Patch count + store size into header.
        out[count_off..count_off+4].copy_from_slice(&3u32.to_be_bytes());
        out[store_off..store_off+4].copy_from_slice(&(store.len() as u32).to_be_bytes());
        let _ = pkg_hdr_start;
        out
    }

    #[test]
    fn parses_minimal_rpm() {
        let blob = make_rpm();
        let p = parse(&blob).unwrap();
        assert_eq!(p.tag_str(RPMTAG_NAME),    Some("test"));
        assert_eq!(p.tag_str(RPMTAG_VERSION), Some("1.0"));
        assert_eq!(p.tag_str(RPMTAG_ARCH),    Some("x86_64"));
    }

    #[test]
    fn rejects_bad_lead() {
        let mut blob = make_rpm();
        blob[0] = 0xff;
        assert_eq!(parse(&blob).unwrap_err(), Error::BadLead);
    }

    #[test]
    fn rejects_truncated() {
        let blob = make_rpm();
        assert_eq!(parse(&blob[..50]).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn missing_tag_returns_none() {
        let blob = make_rpm();
        let p = parse(&blob).unwrap();
        assert_eq!(p.tag_str(RPMTAG_LICENSE), None);
    }
}
