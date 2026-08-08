// What each resolve DECIDES about a page-table leaf, as pure functions of the
// raw entry — separated from the walking, the frame allocation and the HHDM
// writes that surround them.
//
// UNGATED and generic over the walker, so a hosted test drives them against the
// SAME leaf encodings the running kernel uses. The rest of `work/` needs a live
// page table and a physical allocator and cannot be reached hosted; the
// judgements below are the part that decides what happens to a page, and they
// can be.

use hal::pt_walker::PtWalker;
use syscall::errno::Errno;

use crate::userfaultfd::policy::FillKind;

/// The destination of every op that PUBLISHES something at an address — a
/// fill, a poison marker, the receiving half of a move — must be empty.
///
/// EEXIST, not silent replacement, and it covers every kind of entry, not just
/// a resident page: overwriting a swap entry would leak the slot, overwriting a
/// migration entry would lose the page in transit, and overwriting a poison
/// marker would turn contents the monitor declared unrecoverable back into
/// ordinary memory. `None` (no table covers the address) is empty.
/// # C: O(1)
pub fn dst_must_be_empty(raw: Option<u64>) -> Result<(), Errno> {
    if raw.is_some_and(|l| l != 0) { return Err(Errno::Eexist); }
    Ok(())
}

/// What a source leaf holds, and therefore what moving it means.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SrcLeaf {
    /// Nothing: a hole.
    Absent,
    /// A resident page, with its raw entry.
    Present(u64),
    /// A non-present entry naming a page elsewhere (swapped out).
    Swapped(u64),
    /// A page in transit; the move must be retried.
    InFlight,
    /// A marker whose contents cannot be moved anywhere.
    Unmovable,
}

/// Classify one source leaf.
///
/// The ORDER is the contract. A migration entry and a swap entry are both
/// non-present, and a poison marker is neither; testing residency first, then
/// migration, then swap, and treating everything else as unmovable is what
/// keeps a page in transit from being read as a swap entry (which would move a
/// slot reference that does not exist) and a poison marker from being read as
/// either (which would move contents that are gone).
/// # C: O(1)
pub fn classify<W: PtWalker>(raw: Option<u64>) -> SrcLeaf {
    let Some(raw) = raw else { return SrcLeaf::Absent };
    if raw == 0 { return SrcLeaf::Absent; }
    if W::is_valid(raw) { return SrcLeaf::Present(raw); }
    if W::unpack_migration_entry(raw).is_some() { return SrcLeaf::InFlight; }
    if W::unpack_swap_entry(raw).is_some() { return SrcLeaf::Swapped(raw); }
    SrcLeaf::Unmovable
}

/// What one page of a move should do.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MoveStep {
    /// A hole the caller asked to skip. Counts as progress: the destination is
    /// as empty as the source was, which is what the move asked for.
    Skip,
    /// Relocate this raw entry. `resident` marks an entry naming a live frame,
    /// which the caller must prove EXCLUSIVELY owned before moving — taking a
    /// shared page would silently remove it from the mapping that shares it.
    Relocate { raw: u64, resident: bool },
    /// Stop here and report.
    Fail(Errno),
}

/// The per-page move ladder, in its exact order: the destination is checked
/// BEFORE the source, so a move onto an occupied address reports EEXIST
/// whatever the source holds.
/// # C: O(1)
pub fn move_step<W: PtWalker>(dst_raw: Option<u64>, src_raw: Option<u64>, allow_holes: bool)
    -> MoveStep {
    if let Err(e) = dst_must_be_empty(dst_raw) { return MoveStep::Fail(e); }
    match classify::<W>(src_raw) {
        SrcLeaf::Absent => if allow_holes { MoveStep::Skip } else { MoveStep::Fail(Errno::Enoent) },
        SrcLeaf::InFlight => MoveStep::Fail(Errno::Eagain),
        SrcLeaf::Unmovable => MoveStep::Fail(Errno::Efault),
        SrcLeaf::Swapped(raw) => MoveStep::Relocate { raw, resident: false },
        SrcLeaf::Present(raw) => MoveStep::Relocate { raw, resident: true },
    }
}

/// Where one page of a fill takes its contents from.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FillSource {
    /// Publish the page the object already holds; nothing is written.
    Existing,
    /// Write into a frame the OBJECT owns, so every other mapper of it sees the
    /// contents too. A private frame here would leave the object still holding
    /// a hole that other mappers keep seeing.
    IntoObject,
    /// Write into a fresh private frame.
    Fresh,
}

/// Which source a fill uses, from the kind of fill and what the object holds.
///
/// - A continue publishes what the object HAS; if the object has nothing, the
///   monitor is asking to continue something that was never started (EFAULT).
/// - Any other fill into an object refuses an offset the object already holds
///   (EEXIST) rather than overwriting contents another mapper may be using.
/// - With no object behind the mapping there is only the private frame.
/// # C: O(1)
pub fn fill_source(kind: FillKind, has_object: bool, object_holds_page: bool)
    -> Result<FillSource, Errno> {
    match (kind, has_object) {
        (FillKind::Continue, true) =>
            if object_holds_page { Ok(FillSource::Existing) } else { Err(Errno::Efault) },
        (FillKind::Continue, false) => Err(Errno::Efault),
        (_, true) =>
            if object_holds_page { Err(Errno::Eexist) } else { Ok(FillSource::IntoObject) },
        (_, false) => Ok(FillSource::Fresh),
    }
}

/// The leaf a page installed under a write-protecting fill carries: write
/// permission removed AND the marker set, in one value.
///
/// Both halves, always. The marker alone leaves the page writable, so the write
/// the barrier exists to catch never faults; removing write permission alone
/// makes the next write look like an ordinary protection fault, which resolves
/// as a copy instead of being reported.
/// # C: O(1)
pub fn wp_leaf<W: PtWalker>(raw: u64) -> u64 {
    W::leaf_set_uffd_wp(W::leaf_wrprotect(raw))
}

#[cfg(test)]
#[path = "leaf/tests.rs"]
mod tests;
