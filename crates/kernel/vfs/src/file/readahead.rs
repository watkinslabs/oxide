
/// Default readahead window (Linux `VM_READAHEAD_PAGES`, 128 KiB = 32 pages at
/// 4 KiB) — the per-open `f_ra.ra_pages` ceiling.
pub(crate) const DEFAULT_RA_PAGES: u32 = 32;

/// Page size used to convert a byte offset/length into the PAGE-unit index +
/// request count [`File::ra_ondemand`] works in (Linux readahead is page-
/// granular). 4 KiB on both arches' base page. # C: O(1)
pub(crate) const PAGE_SIZE: u64 = 4096;

/// Lock class for `File::f_ra` (never nested with the inode lock). # C: O(1)
pub(crate) struct FileRa;
impl sync::LockClass for FileRa { fn rank() -> u16 { 36 } fn name() -> &'static str { "FileRa" } }

/// `struct file_ra_state` (Linux): per-open sequential readahead window —
/// `start`/`size` in PAGE units, `async_size` the async-trigger margin,
/// `ra_pages` the ceiling. State + Linux window arithmetic; the page-cache fill
/// is the block lane, the mmap `prev_pos`/`mmap_miss` heuristics the mmap lane.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FileRaState { pub start: u64, pub size: u32, pub async_size: u32, pub ra_pages: u32 }

impl FileRaState {
    /// Initial window for a `req`-page read, ≤ `max` (Linux `get_init_ra_size`:
    /// roundup pow2 → 4x small / 2x medium / clamp). # C: O(1)
    pub fn init_ra_size(req: u32, max: u32) -> u32 {
        let mut n = req.max(1).next_power_of_two();
        if n <= max / 32 { n = n.saturating_mul(4); } else if n <= max / 4 { n = n.saturating_mul(2); } else { n = max; }
        n.clamp(1, max.max(1))
    }
    /// Grown window from the current, ≤ `max` (Linux `get_next_ra_size`). # C: O(1)
    pub fn next_ra_size(&self, max: u32) -> u32 {
        let cur = self.size.max(1);
        let n = if cur < max / 16 { cur.saturating_mul(4) } else if cur <= max / 2 { cur.saturating_mul(2) } else { max };
        n.clamp(1, max.max(1))
    }
}
