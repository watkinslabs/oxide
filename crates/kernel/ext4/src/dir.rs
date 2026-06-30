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

/// Errors decoded from `next_entry` / `insert` / `remove`.
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
    /// `insert`: no entry had enough trailing slack to fit a new
    /// entry of the requested size; caller must allocate a new
    /// directory data block.
    Full,
    /// `remove`: target name was not in the block.
    NotFound,
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

/// Bytes consumed by an entry whose name has `name_len` bytes,
/// rounded up to 4-byte alignment per ext4 spec.
/// # C: O(1)
#[inline] pub fn entry_actual_len(name_len: u8) -> usize {
    (8 + name_len as usize + 3) & !3
}

/// In-place insert a directory entry into a dir-block buffer.
/// Walks entries, finds the first whose trailing slack
/// (`rec_len - actual_len`) fits a new entry of size `need`, and
/// splits it: existing entry's rec_len shrinks to actual_len,
/// new entry takes the rest. Returns `DirError::Full` if no slot
/// has enough slack.
///
/// `name.len()` must be ≤ 255. Caller is responsible for
/// matching `file_type` to the child inode's mode.
/// # C: O(N entries)
pub fn insert(buf: &mut [u8], inode: u32, file_type: u8, name: &[u8])
    -> Result<(), DirError>
{
    if name.is_empty() || name.len() > 255 { return Err(DirError::BadNameLen); }
    let need = entry_actual_len(name.len() as u8);
    let mut off = 0usize;
    while off < buf.len() {
        let inode_e = u32::from_le_bytes([buf[off],   buf[off+1], buf[off+2], buf[off+3]]);
        let rec_len = u16::from_le_bytes([buf[off+4], buf[off+5]]) as usize;
        let name_len = buf[off+6];
        if rec_len < 8 || (rec_len & 3) != 0 || off + rec_len > buf.len() {
            return Err(DirError::BadRecLen);
        }
        // Slack = portion of this entry's rec_len beyond what its
        // name actually needs (or the whole rec_len if deleted).
        let used = if inode_e == 0 { 0 } else { entry_actual_len(name_len) };
        let slack = rec_len - used;
        if slack >= need {
            // Shrink predecessor; place new entry in the tail.
            let new_rec = slack;
            let pred_rec = used;
            // For deleted entry (inode==0), used==0 → predecessor
            // rec_len shrinks to 0 which is invalid; in that case
            // overwrite the slot entirely.
            if used == 0 {
                write_entry(&mut buf[off..off+rec_len], inode, rec_len as u16, file_type, name);
            } else {
                buf[off+4..off+6].copy_from_slice(&(pred_rec as u16).to_le_bytes());
                let new_off = off + pred_rec;
                write_entry(&mut buf[new_off..new_off + new_rec], inode, new_rec as u16, file_type, name);
            }
            return Ok(());
        }
        off += rec_len;
    }
    Err(DirError::Full)
}

/// Remove the entry named `name` from the dir-block buffer by
/// coalescing it into its predecessor's `rec_len`. Returns the
/// inode number of the removed entry; `NotFound` if absent.
/// The first entry in a block has no predecessor — we mark it
/// deleted (inode=0) but keep its slot so the block stays
/// well-formed.
/// # C: O(N entries)
pub fn remove(buf: &mut [u8], name: &[u8]) -> Result<u32, DirError> {
    let mut off = 0usize;
    let mut prev_off: Option<usize> = None;
    while off < buf.len() {
        let inode_e  = u32::from_le_bytes([buf[off],   buf[off+1], buf[off+2], buf[off+3]]);
        let rec_len  = u16::from_le_bytes([buf[off+4], buf[off+5]]) as usize;
        let name_len = buf[off+6];
        if rec_len < 8 || (rec_len & 3) != 0 || off + rec_len > buf.len() {
            return Err(DirError::BadRecLen);
        }
        let entry_name = &buf[off+8 .. off+8+name_len as usize];
        if inode_e != 0 && entry_name == name {
            match prev_off {
                Some(po) => {
                    let prev_rec = u16::from_le_bytes([buf[po+4], buf[po+5]]) as usize;
                    let new_prev = prev_rec + rec_len;
                    buf[po+4..po+6].copy_from_slice(&(new_prev as u16).to_le_bytes());
                }
                None => {
                    // First entry in the block: keep slot, mark deleted.
                    buf[off..off+4].copy_from_slice(&0u32.to_le_bytes());
                }
            }
            return Ok(inode_e);
        }
        prev_off = Some(off);
        off += rec_len;
    }
    Err(DirError::NotFound)
}

#[inline]
fn write_entry(slot: &mut [u8], inode: u32, rec_len: u16, file_type: u8, name: &[u8]) {
    slot[0..4].copy_from_slice(&inode.to_le_bytes());
    slot[4..6].copy_from_slice(&rec_len.to_le_bytes());
    slot[6] = name.len() as u8;
    slot[7] = file_type;
    slot[8 .. 8 + name.len()].copy_from_slice(name);
    for b in &mut slot[8 + name.len() .. rec_len as usize] { *b = 0; }
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
    fn insert_uses_trailing_slack_of_last_entry() {
        // 256-byte block. Last entry pads to fill remainder.
        let mut b = std::vec::Vec::new();
        put(&mut b, 11, DT_DIR, b".",  0);                 // 12
        put(&mut b, 1,  DT_DIR, b"..", 0);                 // 12
        put(&mut b, 12, DT_REG, b"keep", 256 - 12 - 12);   // soak
        assert_eq!(b.len(), 256);
        insert(&mut b, 99, DT_REG, b"new").unwrap();
        let names: std::vec::Vec<&[u8]> = {
            let mut v = std::vec::Vec::new();
            iter_active(&b, |e| { v.push(e.name); true }).unwrap();
            v
        };
        assert!(names.contains(&&b"keep"[..]));
        assert!(names.contains(&&b"new"[..]));
        let e = lookup(&b, b"new").unwrap().unwrap();
        assert_eq!(e.inode, 99);
    }

    #[test]
    fn insert_full_when_no_slack() {
        // Single entry that exactly fits its actual_len → no slack.
        let mut b = std::vec::Vec::new();
        put(&mut b, 12, DT_REG, b"foo", 0);  // 12 bytes, no padding
        assert_eq!(insert(&mut b, 99, DT_REG, b"bar"), Err(DirError::Full));
    }

    #[test]
    fn insert_into_deleted_slot() {
        // Delete-marker entry (inode=0) with a wide rec_len that
        // suffices for the new entry verbatim.
        let mut b = std::vec::Vec::new();
        put(&mut b, 0,  DT_REG, b"x", 32);
        put(&mut b, 12, DT_REG, b"keep", 32);
        insert(&mut b, 77, DT_REG, b"new").unwrap();
        let e = lookup(&b, b"new").unwrap().unwrap();
        assert_eq!(e.inode, 77);
    }

    #[test]
    fn remove_coalesces_into_predecessor() {
        let mut b = std::vec::Vec::new();
        put(&mut b, 11, DT_DIR, b".",  0);
        put(&mut b, 1,  DT_DIR, b"..", 0);
        put(&mut b, 12, DT_REG, b"foo", 0);
        put(&mut b, 13, DT_REG, b"bar", 32);  // padded
        let pre_len = b.len();
        let n = remove(&mut b, b"foo").unwrap();
        assert_eq!(n, 12);
        assert_eq!(b.len(), pre_len, "coalesce in-place; buffer length unchanged");
        assert!(lookup(&b, b"foo").unwrap().is_none());
        assert!(lookup(&b, b"bar").unwrap().is_some());
    }

    #[test]
    fn remove_first_entry_marks_deleted() {
        let mut b = std::vec::Vec::new();
        put(&mut b, 12, DT_REG, b"foo", 0);
        put(&mut b, 13, DT_REG, b"bar", 0);
        let n = remove(&mut b, b"foo").unwrap();
        assert_eq!(n, 12);
        assert!(lookup(&b, b"foo").unwrap().is_none());
    }

    #[test]
    fn remove_not_found() {
        let mut b = std::vec::Vec::new();
        put(&mut b, 12, DT_REG, b"foo", 0);
        assert_eq!(remove(&mut b, b"nope"), Err(DirError::NotFound));
    }

    #[test]
    fn dt_constants_pinned() {
        assert_eq!(DT_REG,  1);
        assert_eq!(DT_DIR,  2);
        assert_eq!(DT_LNK,  7);
    }
}
