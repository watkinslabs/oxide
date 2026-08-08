// UFFDIO_MOVE: relocate pages between two anonymous mappings of one address
// space without copying them.
//
// The page keeps its contents and its frame and changes address, so the move
// is a leaf exchange plus a reverse-mapping update — the rmap edge must follow
// the page to its new mapping, or an rmap walk would still find it at the
// address it no longer occupies.

use hal::pt_walker::PtWalker;
use syscall::errno::Errno;

use vmm::address_space::uffd::UffdVma;

use super::arch::{flush, leaf, set_leaf, Walker};
use super::Progress;

const PAGE: u64 = hal::PAGE_SIZE_BYTES;

/// What the source leaf holds, and therefore what moving it means.
enum SrcLeaf {
    /// Nothing: a hole.
    Absent,
    /// A resident page.
    Present(u64),
    /// A non-present entry that names a page elsewhere (swapped out).
    Swapped(u64),
    /// A page in transit; the move must be retried.
    InFlight,
    /// A marker whose contents cannot be moved anywhere.
    Unmovable,
}

/// # C: O(1)
fn classify(raw: Option<u64>) -> SrcLeaf {
    let Some(raw) = raw else { return SrcLeaf::Absent };
    if raw == 0 { return SrcLeaf::Absent; }
    if <Walker as PtWalker>::is_valid(raw) { return SrcLeaf::Present(raw); }
    if <Walker as PtWalker>::unpack_migration_entry(raw).is_some() { return SrcLeaf::InFlight; }
    if <Walker as PtWalker>::unpack_swap_entry(raw).is_some() { return SrcLeaf::Swapped(raw); }
    SrcLeaf::Unmovable
}

/// Move `[src, src+len)` to `[dst, dst+len)`, stopping at the first page that
/// cannot move and reporting how far it got.
///
/// Per page, in order: the destination must be empty (EEXIST otherwise — a
/// move must never destroy a page the process already has there), the source
/// must hold something movable, and a resident source page must be
/// exclusively owned (EBUSY otherwise — moving a page another mapping shares
/// would silently take it away from that mapping).
/// # C: O(len/PAGE) walks
pub fn move_pages(mm: &vmm::AddressSpace, dst: u64, src: u64, len: u64, allow_holes: bool,
                  dst_vma: &UffdVma, src_vma: &UffdVma) -> Progress {
    let mut done = 0u64;
    while done < len {
        let (s, d) = (src + done, dst + done);
        let _pt = mm.lock_page_table();
        if leaf(mm, d).is_some_and(|l| l != 0) { return (done, Some(Errno::Eexist)); }
        match classify(leaf(mm, s)) {
            SrcLeaf::Absent => {
                if !allow_holes { return (done, Some(Errno::Enoent)); }
                // A skipped hole is progress: the destination is as empty as
                // the source was, which is what the move asked for.
            }
            SrcLeaf::InFlight  => return (done, Some(Errno::Eagain)),
            SrcLeaf::Unmovable => return (done, Some(Errno::Efault)),
            // A swapped page names its slot; moving the entry moves the one
            // reference to that slot, and residency does not change.
            SrcLeaf::Swapped(raw) => {
                if let Err(e) = relocate(mm, s, d, raw) { return (done, Some(e)); }
            }
            SrcLeaf::Present(raw) => {
                let pa = raw & <Walker as PtWalker>::PHYS_MASK;
                if !pmm::setup::can_reuse_anon_exclusive(pa) {
                    return (done, Some(Errno::Ebusy));
                }
                if let Err(e) = relocate(mm, s, d, raw) { return (done, Some(e)); }
                reparent(mm, dst_vma, d, pa);
                account(mm, s, d);
            }
        }
        let _ = src_vma;
        done += PAGE;
    }
    (done, None)
}

/// Clear the source leaf and publish the same entry at the destination. The
/// source is cleared FIRST so no window exists in which one page is reachable
/// through two addresses — a window a concurrent fault could turn into a
/// double free.
/// # C: O(walk depth)
fn relocate(mm: &vmm::AddressSpace, s: u64, d: u64, raw: u64) -> Result<(), Errno> {
    if set_leaf(mm, s, 0).is_none() { return Err(Errno::Eagain); }
    flush(mm, s);
    // SAFETY: the page-table lock is held; the entry was just removed from the source address, so publishing it at `d` transfers the one reference it carries rather than duplicating it. Intermediate tables are allocated from the PMM.
    let placed = unsafe {
        hal::pt_walker::map_at_level_with_root::<Walker, _>(
            mm.root_pa(), d, 3, raw, super::arch::hhdm(),
            &mut (|| pmm::setup::alloc_one_frame()))
    };
    if placed.is_err() {
        // Put it back: a move that lost the page would be worse than a move
        // that failed.
        set_leaf(mm, s, raw);
        flush(mm, s);
        return Err(Errno::Enomem);
    }
    flush(mm, d);
    Ok(())
}

/// Move the page's reverse-mapping edge to the destination mapping's anonymous
/// owner at its new index.
/// # C: O(log N)
fn reparent(mm: &vmm::AddressSpace, dst_vma: &UffdVma, d: u64, pa: u64) {
    let Some(uva) = hal::UserVirtAddr::new(d) else { return };
    let Some(anon) = mm.uffd_anon_vma(uva) else { return };
    let idx = ((d - dst_vma.start) / PAGE) as u32;
    // SAFETY: `pa` is the frame now mapped at `d` and nowhere else in this address space, and `anon` is the destination VMA's live anonymous owner; this replaces the edge the source mapping held.
    unsafe { pmm::setup::set_anon_rmap_for_pa(pa, &anon, idx); }
    mm.uffd_mark_anon(uva);
}

/// One resident page left the source mapping and joined the destination one.
/// Both are in the same address space, so this is a transfer, not a change in
/// total residency — but the per-mapping counts must still follow the page.
/// # C: O(log N)
fn account(mm: &vmm::AddressSpace, s: u64, d: u64) {
    if let Some(uva) = hal::UserVirtAddr::new(s) { mm.account_pte_remove_at(uva); }
    if let Some(uva) = hal::UserVirtAddr::new(d) { mm.account_pte_install_at(uva); }
}
