// Where a loader's buffer lands in physical memory.
//
// `kexec_file_load` differs from `kexec_load` in exactly one place: the KERNEL,
// not the caller, chooses every destination address. A loader hands over a
// buffer plus the constraints it must satisfy — alignment, a floor, a ceiling,
// a search direction — and this module finds a hole in RAM that satisfies them
// and does not collide with anything already placed.
//
// Ungated on purpose. The placement algorithm is the part of the file-load path
// that can silently produce an unbootable image: a segment overlapping another
// one, or landing below a kernel's own `pref_address`, boots into rubble with
// no diagnostic anywhere. Every decision here is therefore made against a RAM
// map passed in, so a hosted test can state the machine.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::{KexecSegment, PAGE_SIZE};
use crate::validate::{Error, KResult};

/// Sentinel `mem` meaning "the kernel has not chosen an address yet".
///
/// Zero, because zero is never a legal destination: the first page of physical
/// memory holds the real-mode interrupt vectors on one architecture and is
/// reserved on the other, and no loader in the reference ever asks for it.
pub const MEM_UNKNOWN: u64 = 0;

/// A buffer to place, and the constraints on where it may go.
#[derive(Clone, Debug)]
pub struct KexecBuf {
    /// Bytes of real data.
    pub bufsz: u64,
    /// Bytes reserved at the destination; `>= bufsz`, the tail reads as zero.
    pub memsz: u64,
    /// Required alignment of the destination, raised to at least a page.
    pub align: u64,
    /// Lowest acceptable address, inclusive.
    pub min: u64,
    /// Highest acceptable address, inclusive.
    pub max: u64,
    /// Search from the top of each range down, rather than the bottom up.
    ///
    /// Not cosmetic: one architecture places its kernel bottom-up so the
    /// initramfs and device tree still have room above it, and the other places
    /// everything top-down so the low memory a legacy boot path needs stays
    /// free. A loader that picks the wrong direction still produces a valid
    /// image on a large machine and fails only on a small one.
    pub top_down: bool,
}

impl KexecBuf {
    /// A buffer with no constraint beyond its size — the starting point every
    /// loader narrows.
    /// # C: O(1)
    pub fn new(bufsz: u64, memsz: u64) -> Self {
        Self { bufsz, memsz, align: PAGE_SIZE, min: 0, max: u64::MAX, top_down: false }
    }
}

/// Placement outcome: the chosen physical address.
///
/// `EADDRNOTAVAIL` when no hole satisfies the constraints, which is the
/// reference's answer and the one a loader turns into a retry at a higher
/// floor rather than a failure.
/// # C: O(N_ranges * N_placed) worst case
pub fn locate_mem_hole(
    buf: &KexecBuf, ram: &[(u64, u64)], placed: &[KexecSegment],
) -> KResult<u64> {
    if buf.memsz == 0 { return Err(Error::Inval); }
    let align = core::cmp::max(buf.align, PAGE_SIZE);
    if !align.is_power_of_two() { return Err(Error::Inval); }
    let memsz = buf.memsz.div_ceil(PAGE_SIZE) * PAGE_SIZE;

    // Ranges are visited in address order, and the direction decides which end
    // of the whole map wins — not merely which end of one range.
    let mut ordered: Vec<(u64, u64)> = ram.to_vec();
    ordered.sort_unstable();
    if buf.top_down { ordered.reverse(); }

    for &(rstart, rend) in &ordered {
        let lo = core::cmp::max(rstart, buf.min);
        // `max` is inclusive, so the last byte a placement may occupy is
        // `min(rend - 1, buf.max)`; treating it as exclusive silently loses the
        // final page of every range, which is where a tightly-constrained
        // initramfs is most often the only thing that fits.
        let hi = core::cmp::min(rend.saturating_sub(1), buf.max);
        if hi < lo || hi - lo + 1 < memsz { continue; }
        let found = if buf.top_down {
            scan_down(lo, hi, memsz, align, placed)
        } else {
            scan_up(lo, hi, memsz, align, placed)
        };
        if let Some(at) = found { return Ok(at); }
    }
    Err(Error::AddrNotAvail)
}

/// True when `[at, at + len)` overlaps a destination already claimed.
/// # C: O(N_placed)
pub fn collides(at: u64, len: u64, placed: &[KexecSegment]) -> bool {
    let end = at.saturating_add(len);
    placed.iter().any(|s| {
        s.memsz != 0 && end > s.mem && at < s.mem.saturating_add(s.memsz)
    })
}

fn scan_up(lo: u64, hi: u64, memsz: u64, align: u64, placed: &[KexecSegment]) -> Option<u64> {
    let mut at = lo.div_ceil(align) * align;
    while at.checked_add(memsz)? <= hi + 1 {
        if !collides(at, memsz, placed) { return Some(at); }
        // Step by the alignment, not by a page: a candidate that collided can
        // only be replaced by another aligned one, and stepping a page at a
        // time re-tests addresses that were never legal.
        at = at.checked_add(align)?;
    }
    None
}

fn scan_down(lo: u64, hi: u64, memsz: u64, align: u64, placed: &[KexecSegment]) -> Option<u64> {
    let top = hi + 1 - memsz;
    let mut at = (top / align) * align;
    loop {
        if at < lo { return None; }
        if !collides(at, memsz, placed) { return Some(at); }
        at = at.checked_sub(align)?;
    }
}

/// Add a placed buffer to the segment list, at an address already chosen.
///
/// The `buf` field is an OFFSET into the blob the loader is accumulating, which
/// is what `stage::KernelSource` reads segments out of — the file path never
/// touches user memory.
/// # C: O(1)
pub fn push_segment(segs: &mut Vec<KexecSegment>, blob_off: u64, kb: &KexecBuf, mem: u64) {
    segs.push(KexecSegment {
        buf: blob_off,
        bufsz: kb.bufsz,
        mem,
        memsz: kb.memsz.div_ceil(PAGE_SIZE) * PAGE_SIZE,
    });
}

/// Append `bytes` to `blob`, page-aligning the start, and report the offset it
/// landed at.
///
/// Page alignment is not for the destination — `mem` carries that — but so a
/// segment's source offset and its destination share a page phase. The copy
/// loop reads `PAGE_SIZE` at a time from `buf + off`, so a source that started
/// mid-page would hand every destination page a shifted copy.
/// # C: O(len)
pub fn append_blob(blob: &mut Vec<u8>, bytes: &[u8]) -> u64 {
    let pad = (PAGE_SIZE as usize - blob.len() % PAGE_SIZE as usize) % PAGE_SIZE as usize;
    blob.resize(blob.len() + pad, 0);
    let off = blob.len() as u64;
    blob.extend_from_slice(bytes);
    off
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(mem: u64, memsz: u64) -> KexecSegment {
        KexecSegment { buf: 0, bufsz: 0, mem, memsz }
    }

    const RAM: [(u64, u64); 2] = [(0x10_0000, 0x100_0000), (0x1000_0000, 0x2000_0000)];

    #[test]
    fn bottom_up_takes_the_lowest_aligned_address_that_fits() {
        let mut b = KexecBuf::new(0x1000, 0x1000);
        b.min = 0x10_0000;
        assert_eq!(locate_mem_hole(&b, &RAM, &[]), Ok(0x10_0000));
    }

    #[test]
    fn top_down_takes_the_highest_and_not_merely_the_top_of_the_first_range() {
        // The trap: reversing WITHIN a range but visiting ranges in address
        // order returns an address in low memory on a machine with plenty of
        // high memory, which is exactly where a 64-bit kernel must not land.
        let mut b = KexecBuf::new(0x1000, 0x1000);
        b.top_down = true;
        let got = locate_mem_hole(&b, &RAM, &[]).expect("a hole exists");
        assert!(got >= 0x1000_0000, "{got:#x} is not in the high range");
        assert_eq!(got, 0x2000_0000 - 0x1000);
    }

    #[test]
    fn the_last_page_of_a_range_is_usable() {
        // An inclusive/exclusive slip here loses one page per range, and the
        // page it loses is the one a top-down search wants first.
        let ram = [(0x10_0000u64, 0x11_0000u64)];
        let mut b = KexecBuf::new(0x1000, 0x1000);
        b.top_down = true;
        assert_eq!(locate_mem_hole(&b, &ram, &[]), Ok(0x10_f000));
    }

    #[test]
    fn alignment_is_honoured_and_never_silently_reduced() {
        let mut b = KexecBuf::new(0x1000, 0x1000);
        b.align = 0x20_0000;
        b.min = 0x10_0000;
        let got = locate_mem_hole(&b, &RAM, &[]).expect("a 2 MiB aligned hole exists");
        assert_eq!(got % 0x20_0000, 0);
        assert_eq!(got, 0x20_0000);
    }

    #[test]
    fn a_sub_page_alignment_is_raised_to_a_page() {
        let mut b = KexecBuf::new(16, 16);
        b.align = 16;
        b.min = 0x10_0000;
        let got = locate_mem_hole(&b, &RAM, &[]).expect("a hole exists");
        assert_eq!(got % PAGE_SIZE, 0);
    }

    #[test]
    fn a_placed_segment_is_never_overlapped() {
        let mut b = KexecBuf::new(0x1000, 0x1000);
        b.min = 0x10_0000;
        let placed = [seg(0x10_0000, 0x2000)];
        assert_eq!(locate_mem_hole(&b, &RAM, &placed), Ok(0x10_2000));
        assert!(collides(0x10_1000, 0x1000, &placed));
        assert!(!collides(0x10_2000, 0x1000, &placed));
    }

    #[test]
    fn a_zero_length_placed_segment_blocks_nothing() {
        let placed = [seg(0x10_0000, 0)];
        assert!(!collides(0x10_0000, 0x1000, &placed));
    }

    #[test]
    fn a_ceiling_below_every_range_has_no_answer() {
        let mut b = KexecBuf::new(0x1000, 0x1000);
        b.max = 0x1000;
        assert_eq!(locate_mem_hole(&b, &RAM, &[]), Err(Error::AddrNotAvail));
    }

    #[test]
    fn a_buffer_larger_than_every_range_has_no_answer() {
        let b = KexecBuf::new(0x8000_0000, 0x8000_0000);
        assert_eq!(locate_mem_hole(&b, &RAM, &[]), Err(Error::AddrNotAvail));
    }

    #[test]
    fn a_zero_sized_buffer_is_a_malformed_request_not_a_placement() {
        assert_eq!(locate_mem_hole(&KexecBuf::new(0, 0), &RAM, &[]), Err(Error::Inval));
    }

    #[test]
    fn memsz_is_rounded_to_whole_pages_before_the_collision_test() {
        // A one-byte memsz still occupies a page at the destination, so the
        // next placement must not start inside it.
        let mut b = KexecBuf::new(1, 1);
        b.min = 0x10_0000;
        let at = locate_mem_hole(&b, &RAM, &[]).expect("a hole exists");
        let mut segs = Vec::new();
        push_segment(&mut segs, 0, &b, at);
        assert_eq!(segs[0].memsz, PAGE_SIZE);
        assert!(collides(at + 0x800, 1, &segs));
    }

    #[test]
    fn blob_offsets_keep_every_segment_page_phased() {
        let mut blob = Vec::new();
        let a = append_blob(&mut blob, &[1u8; 100]);
        let b = append_blob(&mut blob, &[2u8; 10]);
        assert_eq!(a, 0);
        assert_eq!(b % PAGE_SIZE, 0);
        assert_eq!(blob[b as usize], 2);
    }
}
