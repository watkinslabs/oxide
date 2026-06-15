// ELF object mapping (docs/59§5, docs/31§4). Maps a PIE/.so into memory:
// reserve one contiguous span (to pick a single load bias), then mmap each
// PT_LOAD file-backed at bias+vaddr with p_flags→prot, zero-fill the bss
// tail, and map any anonymous pages past the file image. W^X enforced.
// Pure layout math is hosted-tested; the mmap drive is freestanding and
// verified end-to-end by the dynamic-run harness.
use elf::{LoadSegment, PFlags};

pub const PAGE: u64 = 4096;

#[inline]
fn floor(x: u64) -> u64 { x & !(PAGE - 1) }
#[inline]
fn ceil(x: u64) -> u64 { (x + PAGE - 1) & !(PAGE - 1) }

/// Page-aligned [start, end) virtual span covering all PT_LOADs (relative to
/// vaddr 0; add the load bias for the runtime range). None if no segments.
///
/// # C: (floor(min vaddr), ceil(max vaddr+memsz)) over loads
pub fn load_span(loads: &[LoadSegment]) -> Option<(u64, u64)> {
    if loads.is_empty() { return None; }
    let mut min = u64::MAX;
    let mut max = 0u64;
    for s in loads {
        if s.vaddr < min { min = s.vaddr; }
        let e = s.vaddr.wrapping_add(s.mem_sz);
        if e > max { max = e; }
    }
    Some((floor(min), ceil(max)))
}

/// Map ELF p_flags to mmap PROT bits, enforcing W^X (a segment that is both
/// W and X drops X — no writable+executable mappings).
///
/// # C: PFlags R/W/X → PROT_READ/WRITE/EXEC, W^X
pub fn seg_prot(flags: PFlags) -> usize {
    let mut p = 0usize;
    if flags.contains(PFlags::R) { p |= 1; } // PROT_READ
    if flags.contains(PFlags::W) { p |= 2; } // PROT_WRITE
    if flags.contains(PFlags::X) && !flags.contains(PFlags::W) { p |= 4; } // PROT_EXEC, W^X
    p
}

#[cfg(feature = "freestanding")]
pub use imp::{map_object, MapError};

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::syscall;
    use elf::ParsedElf;

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum MapError { Reserve, MapSeg, Anon }

    /// Map all PT_LOAD segments of `parsed` (file backed by `fd`) into one
    /// reserved span and return the load bias. For ET_DYN the bias is the
    /// reservation base; for ET_EXEC (fixed vaddr) the bias is 0.
    ///
    /// # C: reserve span, mmap each PT_LOAD file-backed at bias+vaddr
    pub unsafe fn map_object(fd: i32, parsed: &ParsedElf) -> Result<u64, MapError> {
        // SAFETY: drives mmap(2) over fd; every mapping is MAP_FIXED inside
        // the span we just reserved, so no existing mapping is clobbered.
        unsafe {
            let (lo, hi) = load_span(&parsed.loads).ok_or(MapError::Reserve)?;
            let total = (hi - lo) as usize;
            // Reserve the whole range PROT_NONE to claim a contiguous bias.
            let resv = syscall::mmap(0, total, 0, syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS, -1, 0);
            if resv < 0 { return Err(MapError::Reserve); }
            let bias = if parsed.is_pie() { (resv as u64).wrapping_sub(lo) } else { 0 };

            for s in &parsed.loads {
                let prot = seg_prot(s.flags);
                let map_start = bias + floor(s.vaddr);
                let map_end = bias + ceil(s.vaddr + s.file_sz);
                let foff = floor(s.file_off);
                if map_end > map_start {
                    let r = syscall::mmap(map_start as usize, (map_end - map_start) as usize, prot,
                        syscall::MAP_PRIVATE | syscall::MAP_FIXED, fd, foff);
                    if r < 0 { return Err(MapError::MapSeg); }
                }
                // Zero the bss bytes that share the last file-backed page.
                let data_end = bias + s.vaddr + s.file_sz;
                if s.flags.contains(PFlags::W) {
                    let page_end = ceil(s.vaddr + s.file_sz) + bias;
                    let mut p = data_end;
                    while p < page_end { *(p as *mut u8) = 0; p += 1; }
                }
                // Anonymous pages for memsz beyond the file image.
                let alloc_end = bias + ceil(s.vaddr + s.mem_sz);
                if alloc_end > map_end {
                    let r = syscall::mmap(map_end as usize, (alloc_end - map_end) as usize, prot,
                        syscall::MAP_PRIVATE | syscall::MAP_FIXED | syscall::MAP_ANONYMOUS, -1, 0);
                    if r < 0 { return Err(MapError::Anon); }
                }
            }
            Ok(bias)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elf::PFlags;

    fn seg(vaddr: u64, memsz: u64, flags: PFlags) -> LoadSegment {
        LoadSegment { flags, file_off: 0, file_sz: memsz, vaddr, mem_sz: memsz, align: PAGE }
    }

    #[test]
    fn span_covers_all_segments_page_aligned() {
        let loads = [
            seg(0x1000, 0x500, PFlags::R | PFlags::X),
            seg(0x2800, 0x900, PFlags::R | PFlags::W), // ends at 0x3100 → ceil 0x4000
        ];
        assert_eq!(load_span(&loads), Some((0x1000, 0x4000)));
        assert_eq!(load_span(&[]), None);
    }

    #[test]
    fn prot_mapping_and_wx() {
        assert_eq!(seg_prot(PFlags::R), 1);
        assert_eq!(seg_prot(PFlags::R | PFlags::W), 3);
        assert_eq!(seg_prot(PFlags::R | PFlags::X), 5);
        // W+X must drop X (no W^X violation)
        assert_eq!(seg_prot(PFlags::R | PFlags::W | PFlags::X), 3);
    }
}
