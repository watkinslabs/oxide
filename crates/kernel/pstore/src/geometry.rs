// Where the reserved region is, and how it is cut into zones.
//
// Two decisions, both pure and both hosted-tested: which physical range to
// reserve out of the boot memory map, and how a region of that size divides
// into a run of dmesg zones plus one console zone. The reference takes the
// first answer from a platform's device tree and computes the second in
// `ramoops_init_przs`; the arithmetic here is that function's.

use alloc::vec::Vec;

use crate::limits::{MIN_MEM_SIZE, REGION_ALIGN};

/// One zone's placement inside the region.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Zone {
    pub off: usize,
    pub len: usize,
}

/// How a region divides. The dmesg zones are equal-sized and consecutive;
/// the console zone, when there is room for one, follows them.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Layout {
    pub dump: Vec<Zone>,
    pub console: Option<Zone>,
}

/// Cut `region_len` bytes into `record_size`-ish dmesg zones plus a
/// `console_size` console zone.
///
/// The reference's rule: the console zone is taken first at exactly its
/// requested size, the rest is the dump area, the dump COUNT is the area
/// divided by the requested record size, and the actual zone size is then the
/// area divided back by that count — so the whole area is used and no zone is
/// short. A zone size is rounded down to an even number of bytes. A request
/// that leaves no room for even one dump zone produces none rather than a
/// partial one. # C: O(N_zones)
pub fn carve(region_len: usize, record_size: usize, console_size: usize) -> Layout {
    let mut out = Layout::default();
    if region_len == 0 { return out; }
    let console = if console_size > 0 && console_size <= region_len { console_size } else { 0 };
    let dump_area = region_len - console;
    if record_size > 0 && dump_area >= record_size {
        let cnt = dump_area / record_size;
        let zone_sz = (dump_area / cnt) & !1usize;
        if zone_sz > 0 {
            let mut off = 0usize;
            for _ in 0..cnt {
                out.dump.push(Zone { off, len: zone_sz });
                off += zone_sz;
            }
        }
    }
    if console > 0 {
        // Behind the dump zones, so growing the dump area never moves the
        // console zone onto memory a previous boot wrote dump records into.
        out.console = Some(Zone { off: region_len - console, len: console });
    }
    out
}

/// A usable physical range from the boot memory map.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UsableRange {
    pub base: u64,
    pub len: u64,
}

/// Pick the physical base for a `want`-byte reservation.
///
/// The reference is handed an address; nothing here hands us one, so the
/// answer must be derivable from the boot memory map alone AND identical on
/// the next boot of the same machine — a region chosen differently after a
/// reboot finds no records. The rule is therefore positional, not
/// allocation-based: the top of the largest usable range, aligned down.
/// Ties go to the lowest base so the choice cannot depend on map ordering.
///
/// The top is used because the early allocator carves its own bookkeeping
/// from the FRONT of the first range large enough to hold it.
/// # C: O(N_ranges)
pub fn choose_base(ranges: &[UsableRange], want: u64) -> Option<u64> {
    if want == 0 { return None; }
    let mut best: Option<UsableRange> = None;
    for r in ranges {
        // Leave at least as much behind as is taken: a range that would be
        // mostly consumed by the reservation is the wrong one to take it from.
        if r.len < want.saturating_mul(2) { continue; }
        let better = match best {
            None => true,
            Some(b) => r.len > b.len || (r.len == b.len && r.base < b.base),
        };
        if better { best = Some(*r); }
    }
    let r = best?;
    let end = r.base.checked_add(r.len)?;
    let base = (end - want) & !(REGION_ALIGN - 1);
    if base < r.base { return None; }
    Some(base)
}

/// Round a requested region size to something a region can be: page-aligned
/// and at least one minimum-sized zone. # C: O(1)
pub fn round_region_size(want: usize) -> usize {
    let a = REGION_ALIGN as usize;
    let n = (want + a - 1) & !(a - 1);
    if n < MIN_MEM_SIZE { MIN_MEM_SIZE } else { n }
}

#[cfg(test)]
#[path = "tests/geometry.rs"]
mod tests;
