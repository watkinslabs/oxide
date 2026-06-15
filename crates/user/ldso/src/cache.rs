// /etc/ld.so.cache lookup (docs/59§5). glibc writes a new-format cache,
// optionally prefixed by the legacy old-format section for backward compat.
// We locate the new-format struct (`cache_file_new`), then linear-scan its
// entries comparing the soname against each entry's key string. String
// offsets (key/value) are measured from the start of the cache file. Pure
// byte parsing; returns a path slice into the input. Alloc-free.

const MAGIC_NEW: &[u8] = b"glibc-ld.so.cache"; // 17 bytes, no NUL
const MAGIC_OLD: &[u8] = b"ld.so-1.7.0\0"; // 12 bytes, incl NUL
const VERSION: &[u8] = b"1.1"; // 3 bytes

// new-format header size before the entry array: magic(17)+version(3)
// +nlibs(4)+len_strings(4)+flags(1)+pad(3)+ext_off(4)+unused(12) = 48.
const NEW_HDR: usize = 48;
const ENTRY: usize = 24; // file_entry_new: flags(4)+key(4)+value(4)+osver(4)+hwcap(8)
const OLD_HDR: usize = 16; // cache_file: magic(12)+nlibs(4)
const OLD_ENTRY: usize = 12; // file_entry: flags(4)+key(4)+value(4)

#[inline]
fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn align8(x: usize) -> usize { (x + 7) & !7 }

/// Find the byte offset of the new-format `cache_file_new` within the file,
/// or None if absent/malformed.
fn new_base(cache: &[u8]) -> Option<usize> {
    if cache.len() >= NEW_HDR && cache.starts_with(MAGIC_NEW) {
        return Some(0);
    }
    // Old-format prefix: skip to the aligned new struct after old libs.
    if cache.len() >= OLD_HDR && cache.starts_with(MAGIC_OLD) {
        let nlibs = rd_u32(cache, 12)? as usize;
        let off = align8(OLD_HDR + nlibs * OLD_ENTRY);
        if cache.len() >= off + NEW_HDR && cache[off..].starts_with(MAGIC_NEW) {
            return Some(off);
        }
    }
    None
}

fn cstr_at(cache: &[u8], off: usize) -> Option<&[u8]> {
    let s = cache.get(off..)?;
    let end = s.iter().position(|&b| b == 0)?;
    Some(&s[..end])
}

/// Look up `soname` in the cache; return its path (NUL-stripped) on a hit.
///
/// # C: scan cache_file_new entries for key==soname, return its value path
pub fn lookup<'a>(cache: &'a [u8], soname: &[u8]) -> Option<&'a [u8]> {
    let nb = new_base(cache)?;
    // version check (bytes 17..20 of the new struct)
    if cache.get(nb + 17..nb + 20)? != VERSION { return None; }
    let nlibs = rd_u32(cache, nb + 20)? as usize;
    for i in 0..nlibs {
        let e = nb + NEW_HDR + i * ENTRY;
        let key = rd_u32(cache, e + 4)? as usize;
        let value = rd_u32(cache, e + 8)? as usize;
        if cstr_at(cache, key)? == soname {
            return cstr_at(cache, value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    // Build a minimal new-only cache: header, `n` entries, then a string
    // table. key/value are file-relative offsets.
    fn build(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let nlibs = entries.len();
        let strtab_start = NEW_HDR + nlibs * ENTRY;
        let mut strs: Vec<u8> = Vec::new();
        let mut offs: Vec<(usize, usize)> = Vec::new();
        for (k, v) in entries {
            let ko = strtab_start + strs.len();
            strs.extend_from_slice(k);
            strs.push(0);
            let vo = strtab_start + strs.len();
            strs.extend_from_slice(v);
            strs.push(0);
            offs.push((ko, vo));
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC_NEW); // 17
        buf.extend_from_slice(VERSION); // 3
        buf.extend_from_slice(&(nlibs as u32).to_le_bytes()); // nlibs
        buf.extend_from_slice(&(strs.len() as u32).to_le_bytes()); // len_strings
        buf.push(0); // flags
        buf.extend_from_slice(&[0, 0, 0]); // pad
        buf.extend_from_slice(&0u32.to_le_bytes()); // ext_off
        buf.extend_from_slice(&[0u8; 12]); // unused[3]
        assert_eq!(buf.len(), NEW_HDR);
        for (ko, vo) in &offs {
            buf.extend_from_slice(&0u32.to_le_bytes()); // flags
            buf.extend_from_slice(&(*ko as u32).to_le_bytes()); // key
            buf.extend_from_slice(&(*vo as u32).to_le_bytes()); // value
            buf.extend_from_slice(&0u32.to_le_bytes()); // osver
            buf.extend_from_slice(&0u64.to_le_bytes()); // hwcap
        }
        buf.extend_from_slice(&strs);
        buf
    }

    #[test]
    fn new_only_lookup() {
        let c = build(&[
            (b"libc.so.6", b"/lib64/libc.so.6"),
            (b"libm.so.6", b"/lib64/libm.so.6"),
        ]);
        assert_eq!(lookup(&c, b"libc.so.6"), Some(&b"/lib64/libc.so.6"[..]));
        assert_eq!(lookup(&c, b"libm.so.6"), Some(&b"/lib64/libm.so.6"[..]));
        assert_eq!(lookup(&c, b"libz.so.1"), None);
    }

    #[test]
    fn old_prefixed_lookup() {
        // wrap the new cache behind a fake old-format section
        let newc = build(&[(b"libc.so.6", b"/usr/lib64/libc.so.6")]);
        let nlibs_old = 2usize;
        let off = align8(OLD_HDR + nlibs_old * OLD_ENTRY);
        let mut buf = std::vec![0u8; off];
        buf[..MAGIC_OLD.len()].copy_from_slice(MAGIC_OLD);
        buf[12..16].copy_from_slice(&(nlibs_old as u32).to_le_bytes());
        // new-format entry offsets are file-relative; rebuild with base `off`
        // by shifting: simplest is to place newc verbatim and fix offsets.
        // Our parser reads key/value as absolute file offsets, so shift them.
        let mut shifted = newc.clone();
        let nb = 0usize; // newc is new-only at 0
        let nlibs = rd_u32(&newc, nb + 20).unwrap() as usize;
        for i in 0..nlibs {
            let e = NEW_HDR + i * ENTRY;
            let k = rd_u32(&newc, e + 4).unwrap() as usize + off;
            let v = rd_u32(&newc, e + 8).unwrap() as usize + off;
            shifted[e + 4..e + 8].copy_from_slice(&(k as u32).to_le_bytes());
            shifted[e + 8..e + 12].copy_from_slice(&(v as u32).to_le_bytes());
        }
        buf.extend_from_slice(&shifted);
        assert_eq!(lookup(&buf, b"libc.so.6"), Some(&b"/usr/lib64/libc.so.6"[..]));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(lookup(b"not a cache", b"libc.so.6"), None);
        assert_eq!(lookup(&[], b"x"), None);
    }
}
