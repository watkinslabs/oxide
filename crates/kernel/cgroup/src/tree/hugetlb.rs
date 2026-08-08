// hugetlb-controller accounting: hierarchical charge/uncharge against the
// split usage/reservation counters, the interface files over them, and the
// reparenting a departing cgroup's charges undergo.
//
// The charge is refused by the FIRST ancestor whose limit it would exceed, and
// that ancestor — not the cgroup doing the charging — is the one whose failure
// count moves. The two are routinely different: a container hitting its
// parent's limit says so at the parent, which is where an operator looks.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vfs::VfsError;

use super::controllers::HUGETLB;
use super::hugetlb_types::{
    HierarchyKind, HugeAttr, HugeCounterKind, HugeFile, HugeGranule, file_names, parse_file,
    unlimited_bytes,
};
use super::types::{KResult, ROOT, Tree};

/// Outcome of a refused hugetlb charge: the cgroup whose limit stopped it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HugeChargeRefused { pub limit_cgid: u64 }

impl Tree {
    /// Hierarchical charge of one (granule, kind) at `id`: this cgroup's own
    /// pages plus every descendant's. # C: O(subtree)
    pub fn subtree_hugetlb(&self, id: u64, g: HugeGranule, k: HugeCounterKind) -> u64 {
        let n = match self.nodes.get(&id) { Some(n) => n, None => return 0 };
        let mut pages = n.hugetlb.counter(g, k).usage;
        for &child in n.children.values() {
            pages = pages.saturating_add(self.subtree_hugetlb(child, g, k));
        }
        pages
    }

    /// Hierarchical count of refused charges for one granule. # C: O(subtree)
    pub fn subtree_hugetlb_events(&self, id: u64, g: HugeGranule) -> u64 {
        let n = match self.nodes.get(&id) { Some(n) => n, None => return 0 };
        let mut max = n.hugetlb.events(g).max;
        for &child in n.children.values() {
            max = max.saturating_add(self.subtree_hugetlb_events(child, g));
        }
        max
    }

    /// Reserve `huge_pages` pages of `g` against `id`'s ledger of kind `k`.
    ///
    /// Every ancestor with the controller enabled is tested before anything is
    /// committed, so a refusal leaves no partial charge behind. A refusal also
    /// records the event at the charging cgroup and, on a hierarchy that
    /// publishes one, the failure at the limiting cgroup.
    /// # C: O(depth · subtree)
    pub fn try_charge_hugetlb(&mut self, id: u64, g: HugeGranule, k: HugeCounterKind, huge_pages: u64)
        -> Result<(), HugeChargeRefused>
    {
        if huge_pages == 0 { return Ok(()); }
        if !self.nodes.contains_key(&id) { return Err(HugeChargeRefused { limit_cgid: id }); }
        let pages = huge_pages.saturating_mul(g.base_pages());
        let mut cur = Some(id);
        while let Some(a) = cur {
            let n = match self.nodes.get(&a) { Some(n) => n, None => break };
            let gated = n.avail & HUGETLB != 0;
            let max = n.hugetlb.counter(g, k).max;
            if gated {
                if let Some(max) = max {
                    if self.subtree_hugetlb(a, g, k).saturating_add(pages) > max {
                        return Err(self.refuse_hugetlb(id, a, g, k));
                    }
                }
            }
            cur = self.nodes.get(&a).and_then(|n| n.parent);
        }
        if let Some(n) = self.nodes.get_mut(&id) {
            let c = n.hugetlb.counter_mut(g, k);
            c.usage = c.usage.saturating_add(pages);
        }
        self.raise_hugetlb_watermarks(id, g, k);
        Ok(())
    }

    /// Release `huge_pages` pages of `g` from `id`'s ledger of kind `k`.
    /// # C: O(log n)
    pub fn uncharge_hugetlb(&mut self, id: u64, g: HugeGranule, k: HugeCounterKind, huge_pages: u64) {
        if huge_pages == 0 { return; }
        let pages = huge_pages.saturating_mul(g.base_pages());
        if let Some(n) = self.nodes.get_mut(&id) {
            let c = n.hugetlb.counter_mut(g, k);
            c.usage = c.usage.saturating_sub(pages);
        }
    }

    /// Move every hugetlb charge `id` still holds onto its parent, so a cgroup
    /// with outstanding huge pages can be removed instead of being refused.
    /// Returns the parent the charges landed on, or `None` when there was
    /// nothing to move — the caller uses it to retarget the charges' owners.
    /// # C: O(granules)
    pub fn reparent_hugetlb(&mut self, id: u64) -> Option<u64> {
        if id == ROOT { return None; }
        let parent = self.nodes.get(&id)?.parent?;
        let mut moved = false;
        for g in HugeGranule::ALL {
            for k in HugeCounterKind::ALL {
                let pages = match self.nodes.get_mut(&id) {
                    Some(n) => core::mem::take(&mut n.hugetlb.counter_mut(g, k).usage),
                    None => 0,
                };
                if pages == 0 { continue; }
                moved = true;
                if let Some(p) = self.nodes.get_mut(&parent) {
                    let c = p.hugetlb.counter_mut(g, k);
                    c.usage = c.usage.saturating_add(pages);
                }
            }
        }
        if moved { Some(parent) } else { None }
    }

    /// True while `id` still holds a hugetlb usage charge. # C: O(granules)
    pub fn hugetlb_has_usage(&self, id: u64) -> bool {
        self.nodes.get(&id).is_some_and(|n| n.hugetlb.has_usage())
    }

    /// Record a refused charge: the event at the charging cgroup, the failure
    /// at the cgroup whose limit refused it.
    fn refuse_hugetlb(&mut self, charging: u64, limit_cgid: u64, g: HugeGranule, k: HugeCounterKind)
        -> HugeChargeRefused
    {
        if let Some(n) = self.nodes.get_mut(&charging) { n.hugetlb.record_max_event(g); }
        if self.hierarchy.tracks_failcnt() {
            if let Some(n) = self.nodes.get_mut(&limit_cgid) {
                let c = n.hugetlb.counter_mut(g, k);
                c.failcnt = c.failcnt.saturating_add(1);
            }
        }
        HugeChargeRefused { limit_cgid }
    }

    /// Carry every ancestor's high-water mark up to its post-charge
    /// hierarchical usage.
    fn raise_hugetlb_watermarks(&mut self, id: u64, g: HugeGranule, k: HugeCounterKind) {
        let mut cur = Some(id);
        while let Some(a) = cur {
            let now = self.subtree_hugetlb(a, g, k);
            let Some(n) = self.nodes.get_mut(&a) else { break };
            let c = n.hugetlb.counter_mut(g, k);
            if now > c.watermark { c.watermark = now; }
            cur = n.parent;
        }
    }

    /// Set a hugetlb limit. The root has none to set (EINVAL), and a limit
    /// below what is already charged is refused (EBUSY) rather than silently
    /// leaving the counter over its own maximum.
    /// # C: O(subtree)
    pub fn set_hugetlb_max(&mut self, id: u64, g: HugeGranule, k: HugeCounterKind, max: Option<u64>)
        -> KResult<()>
    {
        if id == ROOT { return Err(VfsError::Einval); }
        if !self.nodes.contains_key(&id) { return Err(VfsError::Enoent); }
        if let Some(max) = max {
            if self.subtree_hugetlb(id, g, k) > max { return Err(VfsError::Ebusy); }
        }
        if let Some(n) = self.nodes.get_mut(&id) { n.hugetlb.counter_mut(g, k).max = max; }
        Ok(())
    }

    /// Every hugetlb control-file name this node publishes. The controller has
    /// no interface on the root cgroup, whose charges are the machine's.
    /// # C: O(1)
    pub fn hugetlb_files(&self, id: u64) -> &'static [&'static str] {
        let Some(n) = self.nodes.get(&id) else { return &[] };
        if id == ROOT || n.avail & HUGETLB == 0 { return &[]; }
        file_names(self.hierarchy)
    }

    /// Resolve a control-file name against the hierarchy this tree is.
    /// # C: O(granules · attrs)
    pub fn hugetlb_file(&self, name: &str) -> Option<HugeFile> { parse_file(name, self.hierarchy) }

    /// Read a hugetlb control file. # C: O(subtree)
    pub fn read_hugetlb_file(&self, id: u64, f: HugeFile) -> KResult<Vec<u8>> {
        let n = self.nodes.get(&id).ok_or(VfsError::Enoent)?;
        let c = *n.hugetlb.counter(f.granule, f.kind);
        let page = hal::PAGE_SIZE_BYTES;
        let s: String = match f.attr {
            HugeAttr::Limit => match (c.max, self.hierarchy) {
                (None, HierarchyKind::V2) => "max\n".to_string(),
                (None, HierarchyKind::V1) => format!("{}\n", unlimited_bytes(f.granule)),
                (Some(m), _) => format!("{}\n", m.saturating_mul(page)),
            },
            HugeAttr::Usage => format!("{}\n",
                self.subtree_hugetlb(id, f.granule, f.kind).saturating_mul(page)),
            HugeAttr::MaxUsage => format!("{}\n", c.watermark.saturating_mul(page)),
            HugeAttr::Failcnt => format!("{}\n", c.failcnt),
            HugeAttr::Events => format!("max {}\n", self.subtree_hugetlb_events(id, f.granule)),
            HugeAttr::EventsLocal => format!("max {}\n", n.hugetlb.events(f.granule).max),
            HugeAttr::NumaStat => self.render_hugetlb_numa_stat(id, f.granule),
        };
        Ok(s.into_bytes())
    }

    /// Per-node usage for one granule. This kernel manages a single memory
    /// node, so the node breakdown is one entry that equals the total; the
    /// legacy hierarchy prefixes the hierarchical figure and prints the
    /// cgroup's own usage on a line of its own first.
    fn render_hugetlb_numa_stat(&self, id: u64, g: HugeGranule) -> String {
        let page = hal::PAGE_SIZE_BYTES;
        let hier = self.subtree_hugetlb(id, g, HugeCounterKind::Usage).saturating_mul(page);
        let mut s = String::new();
        if matches!(self.hierarchy, HierarchyKind::V1) {
            let local = self.nodes.get(&id)
                .map(|n| n.hugetlb.counter(g, HugeCounterKind::Usage).usage)
                .unwrap_or(0)
                .saturating_mul(page);
            s.push_str(&format!("total={} N0={}\n", local, local));
            s.push_str(&format!("hierarchical_total={} N0={}\n", hier, hier));
        } else {
            s.push_str(&format!("total={} N0={}\n", hier, hier));
        }
        s
    }

    /// Write a hugetlb control file. Only the limits and the legacy resettable
    /// counters accept a write; everything else is a read-only interface.
    /// # C: O(subtree)
    pub fn write_hugetlb_file(&mut self, id: u64, f: HugeFile, buf: &str) -> KResult<()> {
        match f.attr {
            HugeAttr::Limit => {
                let max = super::hugetlb_types::parse_limit(buf, f.granule, self.hierarchy)
                    .ok_or(VfsError::Einval)?;
                self.set_hugetlb_max(id, f.granule, f.kind, max)
            }
            HugeAttr::MaxUsage => {
                let now = self.subtree_hugetlb(id, f.granule, f.kind);
                let n = self.nodes.get_mut(&id).ok_or(VfsError::Enoent)?;
                n.hugetlb.counter_mut(f.granule, f.kind).watermark = now;
                Ok(())
            }
            HugeAttr::Failcnt => {
                let n = self.nodes.get_mut(&id).ok_or(VfsError::Enoent)?;
                n.hugetlb.counter_mut(f.granule, f.kind).failcnt = 0;
                Ok(())
            }
            _ => Err(VfsError::Eacces),
        }
    }
}
