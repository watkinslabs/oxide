// ext4 directory entry parser per Linux fs/ext4/ext4.h
// `ext4_dir_entry_2`. Entries are variable-length; each
// header is 8 bytes followed by the name (no terminator),
// padded to a 4-byte boundary. The entire entry MUST fit
// inside one filesystem block — rec_len bridges to the next
// entry. The last entry's rec_len consumes the rest of the
// block.

/// `file_type` field values per ext4 spec.
pub const DT_UNKNOWN: u8 = 0;
pub const DT_REG:     u8 = 1;
pub const DT_DIR:     u8 = 2;
pub const DT_CHR:     u8 = 3;
pub const DT_BLK:     u8 = 4;
pub const DT_FIFO:    u8 = 5;
pub const DT_SOCK:    u8 = 6;
pub const DT_LNK:     u8 = 7;

/// Errors decoded from `next_entry`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DirError {
    /// Buffer ran out before a full 8-byte header was available.
    Short,
    /// `rec_len` was less than 8 (header) or not 4-byte aligned.
    BadRecLen,
    /// `rec_len` would run past `buf.len()`.
    Overrun,
    /// `name_len` exceeds `rec_len - 8`.
    BadNameLen,
}

/// One directory entry decoded from a 4 KiB-or-larger block buffer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DirEntry<'a> {
    pub inode:     u32,
    pub rec_len:   u16,
    pub name_len:  u8,
    pub file_type: u8,
    pub name:      &'a [u8],
}

/// Parse one entry at `buf[off..]`. Returns the decoded entry
/// and the offset of the next entry (`off + rec_len`). The
/// caller stops walking when `next_off == buf.len()` (block
/// boundary) or when `inode == 0` (deleted entry — present in
/// ext4, name still valid but should be skipped).
/// # C: O(1) per entry
pub fn next_entry<'a>(buf: &'a [u8], off: usize) -> Result<(DirEntry<'a>, usize), DirError> {
    if off + 8 > buf.len() {
        return Err(DirError::Short);
    }
    let inode    = u32::from_le_bytes([buf[off],   buf[off+1], buf[off+2], buf[off+3]]);
    let rec_len  = u16::from_le_bytes([buf[off+4], buf[off+5]]) as usize;
    let name_len = buf[off+6];
    let ftype    = buf[off+7];
    if rec_len < 8 || (rec_len & 3) != 0 {
        return Err(DirError::BadRecLen);
    }
    if off + rec_len > buf.len() {
        return Err(DirError::Overrun);
    }
    if (name_len as usize) > rec_len - 8 {
        return Err(DirError::BadNameLen);
    }
    let name_end = off + 8 + name_len as usize;
    let name = &buf[off + 8 .. name_end];
    Ok((
        DirEntry {
            inode,
            rec_len:  rec_len as u16,
            name_len,
            file_type: ftype,
            name,
        },
        off + rec_len,
    ))
}

/// Iterator-shape helper: yield every active entry (inode != 0)
/// in `buf` until the buffer ends. Skips deleted entries
/// silently. Returns the first decode error.
/// # C: O(N entries)
pub fn iter_active<'a, F>(buf: &'a [u8], mut f: F) -> Result<(), DirError>
where F: FnMut(&DirEntry<'a>) -> bool
{
    let mut off = 0usize;
    while off < buf.len() {
        let (e, next) = next_entry(buf, off)?;
        if e.inode != 0 {
            if !f(&e) { return Ok(()); }  // caller asked to stop
        }
        off = next;
    }
    Ok(())
}

/// Look up `name` in the directory block. Returns the matching
/// `DirEntry` or `None`. Skips deleted entries.
/// # C: O(N)
pub fn lookup<'a>(buf: &'a [u8], name: &[u8]) -> Result<Option<DirEntry<'a>>, DirError> {
    let mut hit = None;
    iter_active(buf, |e| {
        if e.name == name {
            hit = Some(*e);
            false
        } else {
            true
        }
    })?;
    Ok(hit)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append one ext4_dir_entry_2 to `out`. `rec_len_override`
    /// pads to the requested record length; `0` picks the
    /// minimum (8 + name_len rounded to 4).
    fn put(out: &mut std::vec::Vec<u8>, inode: u32, ftype: u8, name: &[u8], rec_len_override: u16) {
        let nlen = name.len() as u8;
        let min_rec = (8 + nlen as usize + 3) & !3;
        let rec = if rec_len_override == 0 { min_rec } else { rec_len_override as usize };
        let pad = rec - 8 - nlen as usize;
        out.extend_from_slice(&inode.to_le_bytes());
        out.extend_from_slice(&(rec as u16).to_le_bytes());
        out.push(nlen);
        out.push(ftype);
        out.extend_from_slice(name);
        for _ in 0..pad { out.push(0); }
    }

    #[test]
    fn empty_buffer_iter_ok() {
        let buf = std::vec::Vec::<u8>::new();
        let mut hits = 0;
        iter_active(&buf, |_| { hits += 1; true }).unwrap();
        assert_eq!(hits, 0);
    }

    #[test]
    fn parse_single_entry() {
        let mut b = std::vec::Vec::new();
        put(&mut b, 12, DT_REG, b"hello", 0);
        let (e, next) = next_entry(&b, 0).unwrap();
        assert_eq!(e.inode,     12);
        assert_eq!(e.name_len,  5);
        assert_eq!(e.file_type, DT_REG);
        assert_eq!(e.name,      b"hello");
        assert_eq!(next,        b.len());
    }

    #[test]
    fn parse_multiple_entries() {
        let mut b = std::vec::Vec::new();
        put(&mut b, 11, DT_DIR, b".",      0);
        put(&mut b, 1,  DT_DIR, b"..",     0);
        put(&mut b, 12, DT_REG, b"hello",  0);
        put(&mut b, 13, DT_LNK, b"link",   0);
        let mut names = std::vec::Vec::<&[u8]>::new();
        iter_active(&b, |e| { names.push(e.name); true }).unwrap();
        assert_eq!(names, std::vec![&b"."[..], &b".."[..], &b"hello"[..], &b"link"[..]]);
    }

    #[test]
    fn iter_skips_deleted_entries() {
        let mut b = std::vec::Vec::new();
        put(&mut b, 0,  DT_REG, b"deleted", 0);  // inode 0 ⇒ deleted
        put(&mut b, 12, DT_REG, b"alive",   0);
        let mut names = std::vec::Vec::<&[u8]>::new();
        iter_active(&b, |e| { names.push(e.name); true }).unwrap();
        assert_eq!(names, std::vec![&b"alive"[..]]);
    }

    #[test]
    fn lookup_finds_existing() {
        let mut b = std::vec::Vec::new();
        put(&mut b, 11, DT_DIR, b".",   0);
        put(&mut b, 12, DT_REG, b"foo", 0);
        let e = lookup(&b, b"foo").unwrap().expect("hit");
        assert_eq!(e.inode, 12);
    }

    #[test]
    fn lookup_misses_nonexistent() {
        let mut b = std::vec::Vec::new();
        put(&mut b, 12, DT_REG, b"foo", 0);
        assert!(lookup(&b, b"bar").unwrap().is_none());
    }

    #[test]
    fn rejects_short_buffer() {
        let b = std::vec![0u8; 4];
        assert_eq!(next_entry(&b, 0), Err(DirError::Short));
    }

    #[test]
    fn rejects_bad_rec_len() {
        // rec_len=4 would mean header overlapping — must be ≥8
        let mut b = std::vec::Vec::<u8>::new();
        b.extend_from_slice(&12u32.to_le_bytes());
        b.extend_from_slice(&4u16.to_le_bytes());   // rec_len=4
        b.push(0); b.push(DT_REG);
        assert_eq!(next_entry(&b, 0), Err(DirError::BadRecLen));
    }

    #[test]
    fn rejects_overrun_rec_len() {
        // rec_len claims 24 bytes but buffer is only 16.
        let mut b = std::vec![0u8; 16];
        b[0..4].copy_from_slice(&12u32.to_le_bytes());
        b[4..6].copy_from_slice(&24u16.to_le_bytes());
        assert_eq!(next_entry(&b, 0), Err(DirError::Overrun));
    }

    #[test]
    fn rejects_bad_name_len() {
        // rec_len=12 (header + 4-byte slot) but name_len=99 claims more.
        let mut b = std::vec![0u8; 12];
        b[0..4].copy_from_slice(&12u32.to_le_bytes());
        b[4..6].copy_from_slice(&12u16.to_le_bytes());
        b[6] = 99;
        b[7] = DT_REG;
        assert_eq!(next_entry(&b, 0), Err(DirError::BadNameLen));
    }

    #[test]
    fn last_entry_consumes_block_tail() {
        // ext4 dirs pad the last entry's rec_len out to the
        // block boundary. Validate the parser stops cleanly.
        let mut b = std::vec::Vec::new();
        put(&mut b, 12, DT_REG, b"a",   16);     // 16 bytes
        put(&mut b, 13, DT_REG, b"b",   240);    // pads to 240, total 256
        let mut names = std::vec::Vec::<&[u8]>::new();
        iter_active(&b, |e| { names.push(e.name); true }).unwrap();
        assert_eq!(names, std::vec![&b"a"[..], &b"b"[..]]);
    }

    #[test]
    fn dt_constants_pinned() {
        assert_eq!(DT_REG,  1);
        assert_eq!(DT_DIR,  2);
        assert_eq!(DT_LNK,  7);
    }
}
