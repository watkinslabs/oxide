// hugetlb-controller entry points for the huge-page pool, and the removal path
// that has to reparent a departing cgroup's charges.
//
// The pool charges here; the hierarchy state lives in `tree::hugetlb`. Keeping
// these out of the crate root is what stops the root from growing a fourth
// controller's glue.

use vfs::{KResult, VfsError};

use crate::state::{self, TREE};
use crate::tree::{HugeChargeRefused, HugeCounterKind, HugeGranule};

/// Charge `huge_pages` pages of `granule` to `cgid`'s hugetlb ledger of
/// `kind`. `Err` names the ancestor whose limit refused it; the caller reports
/// ENOMEM, which is what a huge-page allocation over a limit gets. Succeeds
/// while the hierarchy is unmounted, like every other charge in this crate.
/// # C: O(depth · subtree)
pub fn try_charge_hugetlb(cgid: u64, granule: HugeGranule, kind: HugeCounterKind, huge_pages: u64)
    -> Result<(), HugeChargeRefused>
{
    let mut t = TREE.lock();
    if !t.is_mounted() { return Ok(()); }
    t.try_charge_hugetlb(cgid, granule, kind, huge_pages)
}

/// Release a hugetlb charge from the cgroup that took it. # C: O(log n)
pub fn uncharge_hugetlb(cgid: u64, granule: HugeGranule, kind: HugeCounterKind, huge_pages: u64) {
    let mut t = TREE.lock();
    if t.is_mounted() { t.uncharge_hugetlb(cgid, granule, kind, huge_pages); }
}

/// Remove child `name` of `parent_cgid`.
///
/// Outstanding huge-page charges do not block the removal: they move to the
/// parent, which is what keeps a container teardown from wedging on pages its
/// processes still hold. The owner records the pool keeps have to be
/// retargeted to match, and that happens with the hierarchy lock released.
/// # C: O(log n) + O(pool records) when charges moved
pub fn remove_child(parent_cgid: u64, name: &str) -> KResult<()> {
    let id = {
        let t = TREE.lock();
        *t.node(parent_cgid).ok_or(VfsError::Enoent)?
            .children.get(name).ok_or(VfsError::Enoent)?
    };
    let reparented = {
        let mut t = TREE.lock();
        let to = t.reparent_hugetlb(id);
        t.remove(id)?;
        to
    };
    if let Some(to) = reparented {
        if let Some(hook) = state::hugetlb_reparent_hook() { hook(id, to); }
    }
    Ok(())
}
