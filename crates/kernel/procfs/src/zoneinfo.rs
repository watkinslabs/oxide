// /proc/zoneinfo — the per-zone rows of the buddy allocator. One block per
// zone slot, populated or not: the lowmem-reserve matrix is a function of the
// whole zone set, so a suppressed zone would hide the effect the file exists
// to show.
//
// The renderer is deliberately ungated and takes the rows as a value, so the
// layout is checkable without a kernel target and without an allocator.

use alloc::vec::Vec;
use pmm::zone::NR_ZONES;
use pmm::ZoneStat;

/// Right-aligned width the zone name is printed in.
const ZONE_NAME_WIDTH: usize = 8;

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

/// Render every zone row of one memory node. # C: O(NR_ZONES^2)
pub fn render(node: u32, zones: &[ZoneStat; NR_ZONES]) -> Vec<u8> {
    use core::fmt::Write;
    let mut out: Vec<u8> = Vec::with_capacity(NR_ZONES * 320);
    for z in zones.iter() {
        let name = z.zone.name();
        let _ = write!(VecFmt(&mut out), "Node {node}, zone {name:>ZONE_NAME_WIDTH$}");
        // Boost and CMA have no producer here and are reported as the zero
        // they hold, not omitted: a reader that indexes the block by line
        // would otherwise mis-read every field below them.
        let _ = write!(VecFmt(&mut out),
            "\n  pages free     {}\
             \n        boost    {}\
             \n        min      {}\
             \n        low      {}\
             \n        high     {}\
             \n        promo    {}\
             \n        spanned  {}\
             \n        present  {}\
             \n        managed  {}\
             \n        cma      {}",
            z.free_pages, 0, z.wmark.min, z.wmark.low, z.wmark.high, z.wmark.promo,
            z.spanned_pages, z.present_pages, z.managed_pages, 0);
        let _ = write!(VecFmt(&mut out), "\n        protection: ({}", z.lowmem_reserve[0]);
        for r in z.lowmem_reserve.iter().skip(1) { let _ = write!(VecFmt(&mut out), ", {r}"); }
        out.extend_from_slice(b")\n");
        // Nothing below the reserve row describes an unpopulated zone.
        if z.present_pages == 0 { continue; }
        let _ = write!(VecFmt(&mut out),
            "  node_unreclaimable:  {}\
             \n  start_pfn:           {}\
             \n  reserved_highatomic: {}\
             \n  free_highatomic:     {}\n",
            0, z.start_pfn, 0, 0);
    }
    out
}

/// `/proc/buddyinfo` body: one row per populated zone, per-order free-block
/// counts. # C: O(NR_ZONES*ORDERS)
pub fn render_buddyinfo(node: u32, zones: &[ZoneStat; NR_ZONES]) -> Vec<u8> {
    use core::fmt::Write;
    let mut out: Vec<u8> = Vec::with_capacity(NR_ZONES * 192);
    for z in zones.iter() {
        if z.present_pages == 0 { continue; }
        let name = z.zone.name();
        let _ = write!(VecFmt(&mut out), "Node {node}, zone {name:>ZONE_NAME_WIDTH$} ");
        for c in z.free_orders.iter() { let _ = write!(VecFmt(&mut out), "{c:>6} "); }
        out.push(b'\n');
    }
    out
}

/// The node every zone here belongs to. One memory node exists.
pub const NODE: u32 = 0;

#[cfg(target_os = "oxide-kernel")]
mod live {
    use alloc::vec::Vec;
    use vfs::{Ino, InodeRef};

    fn zones() -> Option<[pmm::ZoneStat; pmm::zone::NR_ZONES]> {
        Some(pmm::setup::pmm_static()?.zone_snapshot())
    }

    fn zoneinfo_body() -> Vec<u8> {
        match zones() { Some(z) => super::render(super::NODE, &z), None => Vec::new() }
    }

    fn buddyinfo_body() -> Vec<u8> {
        match zones() { Some(z) => super::render_buddyinfo(super::NODE, &z), None => Vec::new() }
    }

    /// `/proc/zoneinfo` inode. # C: O(1)
    pub fn make_proc_zoneinfo() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::ZONEINFO as Ino, zoneinfo_body) }

    /// `/proc/buddyinfo` inode. # C: O(1)
    pub fn make_proc_buddyinfo() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::BUDDYINFO as Ino, buddyinfo_body) }
}

#[cfg(target_os = "oxide-kernel")]
pub use live::{make_proc_buddyinfo, make_proc_zoneinfo};

#[cfg(test)]
mod tests;
