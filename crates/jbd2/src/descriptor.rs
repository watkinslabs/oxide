// Descriptor block: lists the target fs blocks for the data
// blocks immediately following in the journal. Each entry
// (`journal_block_tag_s` in fs/jbd2) is 8 (legacy 32-bit) or
// 16 (64BIT feature) bytes:
//
//   u32 t_blocknr_lo
//   u32 t_flags
//   [u32 t_blocknr_hi  if 64BIT]
//   [u8 t_uuid[16]     if !SAME_UUID]
//
// The list ends when t_flags has TAG_FLAG_LAST set.

extern crate alloc;
use alloc::vec::Vec;

pub const TAG_FLAG_ESCAPE:    u32 = 0x01;
pub const TAG_FLAG_SAME_UUID: u32 = 0x02;
pub const TAG_FLAG_DELETED:   u32 = 0x04;
pub const TAG_FLAG_LAST:      u32 = 0x08;

/// One on-disk descriptor entry decoded.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DescriptorTag {
    /// Target fs block number to which the next journal data
    /// block is to be applied during replay.
    pub blocknr:  u64,
    pub flags:    u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DescriptorEntry {
    pub tag:      DescriptorTag,
    /// Bytes consumed in the descriptor block by this tag (incl.
    /// optional UUID padding). Caller advances the offset by this.
    pub on_disk:  usize,
}

/// Iterator that walks descriptor tags out of a descriptor block
/// (already-stripped header). The caller hands the iterator the
/// payload starting at offset `12` from the descriptor block's
/// start (i.e. the bytes after the `BlockHeader`).
pub struct DescriptorIter<'a> {
    pub buf:    &'a [u8],
    pub off:    usize,
    pub bit64:  bool,
    pub done:   bool,
    /// First UUID seen — subsequent SAME_UUID-tagged entries
    /// inherit it. JBD2 always emits a UUID on the first tag.
    pub _first_uuid: [u8; 16],
}

impl<'a> DescriptorIter<'a> {
    /// # C: O(1)
    pub fn new(buf: &'a [u8], bit64: bool) -> Self {
        Self { buf, off: 0, bit64, done: false, _first_uuid: [0u8; 16] }
    }
}

impl<'a> Iterator for DescriptorIter<'a> {
    type Item = DescriptorEntry;
    fn next(&mut self) -> Option<DescriptorEntry> {
        if self.done { return None; }
        let off = self.off;
        let min = if self.bit64 { 16 } else { 8 };
        if off + min > self.buf.len() { self.done = true; return None; }
        let blocknr_lo = u32::from_be_bytes([self.buf[off], self.buf[off+1], self.buf[off+2], self.buf[off+3]]) as u64;
        let flags      = u32::from_be_bytes([self.buf[off+4], self.buf[off+5], self.buf[off+6], self.buf[off+7]]);
        let mut consume = min;
        let mut blocknr = blocknr_lo;
        if self.bit64 {
            let blocknr_hi = u32::from_be_bytes([self.buf[off+8], self.buf[off+9], self.buf[off+10], self.buf[off+11]]) as u64;
            blocknr |= blocknr_hi << 32;
        }
        // Skip UUID for the first tag of a transaction (or any tag
        // not flagged SAME_UUID). The UUID is 16 bytes.
        if (flags & TAG_FLAG_SAME_UUID) == 0 {
            if off + consume + 16 > self.buf.len() { self.done = true; return None; }
            consume += 16;
        }
        let entry = DescriptorEntry {
            tag: DescriptorTag { blocknr, flags },
            on_disk: consume,
        };
        if (flags & TAG_FLAG_LAST) != 0 { self.done = true; }
        self.off += consume;
        Some(entry)
    }
}

/// Drain a descriptor block into a Vec for callers that prefer
/// random access.
/// # C: O(N tags)
pub fn collect_tags(buf: &[u8], bit64: bool) -> Vec<DescriptorTag> {
    DescriptorIter::new(buf, bit64).map(|e| e.tag).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(out: &mut std::vec::Vec<u8>, v: u32) { out.extend_from_slice(&v.to_be_bytes()); }
    fn put_uuid(out: &mut std::vec::Vec<u8>) { for _ in 0..16 { out.push(0xAA); } }

    #[test]
    fn walk_two_legacy_tags() {
        // Tag A: blocknr=100, flags=0 → expects UUID (16 bytes)
        // Tag B: blocknr=200, flags=SAME_UUID|LAST → no UUID
        let mut b = std::vec::Vec::new();
        put32(&mut b, 100); put32(&mut b, 0);                    put_uuid(&mut b);
        put32(&mut b, 200); put32(&mut b, TAG_FLAG_SAME_UUID | TAG_FLAG_LAST);
        let v: std::vec::Vec<_> = DescriptorIter::new(&b, false).collect();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].tag.blocknr, 100);
        assert_eq!(v[1].tag.blocknr, 200);
        assert!((v[1].tag.flags & TAG_FLAG_LAST) != 0);
    }

    #[test]
    fn walk_64bit_tag() {
        // 64bit: 16 bytes per tag (no UUID with SAME_UUID|LAST).
        let mut b = std::vec::Vec::new();
        put32(&mut b, 0x0000_0064);  // blocknr_lo
        put32(&mut b, TAG_FLAG_SAME_UUID | TAG_FLAG_LAST);
        put32(&mut b, 1);            // blocknr_hi
        put32(&mut b, 0);            // unused
        let v: std::vec::Vec<_> = DescriptorIter::new(&b, true).collect();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].tag.blocknr, 0x0000_0001_0000_0064);
    }

    #[test]
    fn stops_on_truncated_buffer() {
        let b = std::vec![0u8; 4];  // < 8 bytes minimum
        let v: std::vec::Vec<_> = DescriptorIter::new(&b, false).collect();
        assert!(v.is_empty());
    }
}
