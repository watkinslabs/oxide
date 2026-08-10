// Offset-addressable reads over the file `/proc/kcore` presents.
//
// A consumer seeks: it reads the header, computes an offset from an address,
// and reads there. So every read must answer for the offset it was given and
// nothing else — a read that only worked from zero, or that returned the header
// again after a seek, hands the caller header bytes where it expected memory.
//
// A read that lands outside every described region returns ZEROES, not an
// error. The file is one linear span with holes in it by construction, and a
// consumer stepping across a gap between two regions must not see a short read.

extern crate alloc;
use alloc::vec::Vec;

use super::{layout, Map};

/// The fixed prefix: header, program-header table, notes, then zero padding up
/// to the data area. Its length is the data offset by construction, so the two
/// cannot drift apart. # C: O(N regions + len notes)
pub fn header_bytes(map: &Map) -> Vec<u8> {
    let data = layout::data_offset(&map.regions, map.notes.len()) as usize;
    let mut out = Vec::with_capacity(data);
    out.extend_from_slice(&layout::ehdr(map.machine, layout::phnum(&map.regions)));
    out.extend_from_slice(&layout::phdr_table(map));
    out.extend_from_slice(&map.notes);
    out.resize(data, 0);
    out
}

/// Fill `buf` with the file's bytes at `off`, returning how many were written
/// (`0` at or past end of file).
///
/// `fetch(vaddr, dst)` copies described memory; it is the only part of a read
/// that touches the machine, which is what keeps the whole layout above
/// checkable against a synthetic region list.
/// # C: O(len buf + N regions)
pub fn read_at<F>(map: &Map, off: u64, buf: &mut [u8], mut fetch: F) -> usize
where F: FnMut(u64, &mut [u8])
{
    let size = layout::file_size(map);
    if off >= size || buf.is_empty() { return 0; }
    let n = core::cmp::min(buf.len() as u64, size - off) as usize;
    let out = &mut buf[..n];
    // Holes are zero, and a region only overwrites the span it covers.
    for b in out.iter_mut() { *b = 0; }

    let hdr = header_bytes(map);
    let data = hdr.len() as u64;
    if off < data {
        let take = core::cmp::min(n as u64, data - off) as usize;
        let at = off as usize;
        out[..take].copy_from_slice(&hdr[at..at + take]);
    }

    let end = off + n as u64;
    for r in map.regions.iter() {
        if r.size == 0 { continue; }
        let r_start = layout::offset_of(map.page_offset, data, r.vaddr);
        let r_end = r_start.wrapping_add(r.size);
        if r_end <= off || r_start >= end { continue; }
        let from = core::cmp::max(r_start, off);
        let to = core::cmp::min(r_end, end);
        let dst = ((from - off) as usize)..((to - off) as usize);
        fetch(r.vaddr + (from - r_start), &mut out[dst]);
    }
    n
}

#[cfg(test)]
#[path = "tests/read.rs"]
mod tests;
