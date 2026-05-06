// cpio newc (SVR4) archive parser. RPM payloads use this format
// (sometimes wrapped by gzip/xz/zstd, which the caller decompresses
// first). Each entry begins with a 110-byte ASCII header:
//
//   Magic:     6  ASCII   "070701" or "070702" (with crc)
//   ino:       8  hex
//   mode:      8  hex
//   uid:       8  hex
//   gid:       8  hex
//   nlink:     8  hex
//   mtime:     8  hex
//   filesize:  8  hex
//   devmajor:  8  hex
//   devminor:  8  hex
//   rdevmajor: 8  hex
//   rdevminor: 8  hex
//   namesize:  8  hex (includes trailing NUL)
//   check:     8  hex
//
// Then `namesize` bytes (NUL-terminated name), padded to 4-byte
// boundary. Then `filesize` bytes of file data, padded to 4-byte
// boundary. Stream ends when name == "TRAILER!!!".

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;
use alloc::vec::Vec;

pub const MAGIC_NEWC:    &[u8; 6] = b"070701";
pub const MAGIC_NEWC_CRC: &[u8; 6] = b"070702";
pub const TRAILER_NAME:  &str     = "TRAILER!!!";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    BadMagic,
    Truncated,
    BadHexField,
}

#[derive(Clone, Debug)]
pub struct Entry<'a> {
    pub name:   &'a str,
    pub mode:   u32,
    pub uid:    u32,
    pub gid:    u32,
    pub mtime:  u32,
    pub data:   &'a [u8],
}

#[inline] fn hex_u32(s: &[u8]) -> Result<u32, Error> {
    let mut v: u32 = 0;
    for &b in s {
        v = v.wrapping_shl(4) | match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'a'..=b'f' => (b - b'a' + 10) as u32,
            b'A'..=b'F' => (b - b'A' + 10) as u32,
            _ => return Err(Error::BadHexField),
        };
    }
    Ok(v)
}

#[inline] fn align4(x: usize) -> usize { (x + 3) & !3 }

/// Parse the whole archive. Each entry's `data` is borrowed from
/// the source slice (zero-copy). Stops at TRAILER!!!.
/// # C: O(N)
pub fn parse(buf: &[u8]) -> Result<Vec<Entry<'_>>, Error> {
    let mut out = Vec::new();
    let mut p = 0;
    loop {
        if p + 110 > buf.len() { return Err(Error::Truncated); }
        let magic = &buf[p..p+6];
        if magic != MAGIC_NEWC && magic != MAGIC_NEWC_CRC {
            return Err(Error::BadMagic);
        }
        // Field offsets: 6+0=6 (ino), 6+8=14 (mode), 22 uid, 30 gid,
        // 38 nlink, 46 mtime, 54 filesize, 62 devmaj, 70 devmin,
        // 78 rdevmaj, 86 rdevmin, 94 namesize, 102 check.
        let mode     = hex_u32(&buf[p+14..p+22])?;
        let uid      = hex_u32(&buf[p+22..p+30])?;
        let gid      = hex_u32(&buf[p+30..p+38])?;
        let mtime    = hex_u32(&buf[p+46..p+54])?;
        let filesize = hex_u32(&buf[p+54..p+62])? as usize;
        let namesize = hex_u32(&buf[p+94..p+102])? as usize;

        let name_start = p + 110;
        let name_end_n = name_start + namesize;
        if name_end_n > buf.len() { return Err(Error::Truncated); }
        // Strip NUL.
        let name_bytes = &buf[name_start..name_end_n - 1];
        let name = core::str::from_utf8(name_bytes).map_err(|_| Error::BadHexField)?;

        // Header + name padded to 4-byte boundary.
        let after_name = align4(name_end_n);
        let data_end_n = after_name + filesize;
        if data_end_n > buf.len() { return Err(Error::Truncated); }
        let data = &buf[after_name..data_end_n];
        let next = align4(data_end_n);

        if name == TRAILER_NAME { break; }
        out.push(Entry { name, mode, uid, gid, mtime, data });
        p = next;
        if p >= buf.len() { return Err(Error::Truncated); }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    fn pad4(v: &mut Vec<u8>) { while v.len() % 4 != 0 { v.push(0); } }

    fn write_entry(out: &mut Vec<u8>, name: &str, data: &[u8]) {
        let _8x = |n: u32| format!("{:08x}", n);
        out.extend_from_slice(b"070701");
        out.extend_from_slice(_8x(0).as_bytes());          // ino
        out.extend_from_slice(_8x(0o100644).as_bytes());   // mode
        out.extend_from_slice(_8x(0).as_bytes());          // uid
        out.extend_from_slice(_8x(0).as_bytes());          // gid
        out.extend_from_slice(_8x(1).as_bytes());          // nlink
        out.extend_from_slice(_8x(0).as_bytes());          // mtime
        out.extend_from_slice(_8x(data.len() as u32).as_bytes()); // filesize
        out.extend_from_slice(_8x(0).as_bytes());          // devmajor
        out.extend_from_slice(_8x(0).as_bytes());          // devminor
        out.extend_from_slice(_8x(0).as_bytes());          // rdevmajor
        out.extend_from_slice(_8x(0).as_bytes());          // rdevminor
        out.extend_from_slice(_8x((name.len() + 1) as u32).as_bytes()); // namesize
        out.extend_from_slice(_8x(0).as_bytes());          // check
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        pad4(out);
        out.extend_from_slice(data);
        pad4(out);
    }

    fn write_trailer(out: &mut Vec<u8>) {
        write_entry(out, "TRAILER!!!", b"");
    }

    #[test]
    fn roundtrips_two_entries() {
        let mut blob = Vec::new();
        write_entry(&mut blob, "hello.txt",  b"hi\n");
        write_entry(&mut blob, "/etc/hosts", b"127.0.0.1 localhost\n");
        write_trailer(&mut blob);

        let entries = parse(&blob).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, b"hi\n");
        assert_eq!(entries[1].name, "/etc/hosts");
        assert_eq!(entries[1].mode, 0o100644);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = std::vec![0u8; 110];
        blob[0..6].copy_from_slice(b"abcdef");
        assert_eq!(parse(&blob).unwrap_err(), Error::BadMagic);
    }

    #[test]
    fn rejects_truncated() {
        let mut blob = Vec::new();
        write_entry(&mut blob, "f", b"x");
        // Drop trailer + final padding.
        blob.truncate(blob.len() - 8);
        assert!(matches!(parse(&blob).unwrap_err(),
                         Error::Truncated | Error::BadMagic));
    }

    #[test]
    fn empty_archive_just_trailer() {
        let mut blob = Vec::new();
        write_trailer(&mut blob);
        let entries = parse(&blob).unwrap();
        assert!(entries.is_empty());
    }
}
