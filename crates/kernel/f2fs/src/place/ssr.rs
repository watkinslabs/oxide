//! Whether a log opens a fresh segment or recycles a partly-used one.
//!
//! Appending to an empty segment is what makes the volume's writes sequential,
//! so it is what a log does while there is space to do it with. Recycling —
//! taking a segment that still holds live blocks and writing into the gaps
//! between them — costs a scattered write and buys the one thing the volume
//! runs out of first: SECTIONS the cleaner can move live blocks into.
//!
//! The decision is therefore about PRESSURE, and it is made per allocation,
//! not per mount. A mount that recycled always would never write sequentially;
//! one that never recycled would hand the cleaner an empty reserve and a volume
//! with nothing free, which is the state a log-structured filesystem cannot
//! recover from — the cleaner needs somewhere to put what it moves.
//!
//! What the mount ASKED for does not appear here, and that is deliberate: the
//! option that names an allocation mode moves the free-segment search's
//! starting point ([`next_segno_hint`]), which is a different question from
//! whether a segment is recycled at all.

/// Everything the pressure decision reads.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Need {
    /// The mount never recycles.
    pub lfs: bool,
    /// The cleaner has been put in its most urgent mode, so every section it
    /// can be handed is one it needs.
    pub gc_urgent_high: bool,
    /// Checkpointing is off, so no space comes back until it is on again.
    pub cp_disabled: bool,
    /// Sections the allocator could still open.
    pub free_sections: u32,
    /// Sections the metadata this mount has changed will need when it lands.
    /// Dentry blocks count TWICE: a directory's block is written and the node
    /// naming it is written after, and both land before the space is back.
    pub node_secs: u32,
    pub dent_secs: u32,
    pub imeta_secs: u32,
    /// The floor a mount keeps above the reserve before it starts recycling.
    pub min_ssr_sections: u32,
    /// Sections held back so the cleaner always has a destination.
    pub reserved_sections: u32,
}

/// Whether the next allocation should recycle rather than append.
/// # C: O(1)
pub fn need_ssr(n: &Need) -> bool {
    if n.lfs { return false; }
    if n.gc_urgent_high { return true; }
    if n.cp_disabled { return true; }
    let required = n.node_secs
        .saturating_add(2u32.saturating_mul(n.dent_secs))
        .saturating_add(n.imeta_secs)
        .saturating_add(n.min_ssr_sections)
        .saturating_add(n.reserved_sections);
    n.free_sections <= required
}

/// Sections `pages` dirty blocks will occupy once they are placed. # C: O(1)
pub fn secs_for_pages(pages: usize, blks_per_sec: u32) -> u32 {
    let per = blks_per_sec.max(1);
    (pages as u64).div_ceil(u64::from(per)).min(u64::from(u32::MAX)) as u32
}

/// What the choice between a fresh segment and a recycled one reads, beside
/// the pressure above.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Choice {
    /// The volume's checkpoints carry a checksum a replay can verify.
    pub crc_recovery: bool,
    /// The log being reopened is the one a file's own node blocks go to.
    pub warm_node_log: bool,
    /// The log was APPENDING rather than recycling.
    pub appending: bool,
    /// The segment after the one being closed is free, and inside the same
    /// section.
    pub next_seg_free: bool,
    pub cp_disabled: bool,
}

/// Whether the log must open a FRESH segment.
///
/// Three reasons, ahead of the pressure question:
///
/// - A volume whose checkpoints carry no checksum cannot have a replay verify
///   the node chain, and a file's node blocks are what that chain is made of —
///   so they are kept in whole appended segments, where their order alone says
///   which came last.
/// - The segment straight after the one being closed is free and in the same
///   section: appending there keeps the log contiguous and costs nothing, so
///   there is no reason to go looking for gaps.
/// - Nothing is pressing. Recycling is the answer to pressure and buys nothing
///   without it.
/// # C: O(1), plus one call of `need_ssr` when the first two do not decide
pub fn need_new_seg(c: &Choice, need_ssr: impl FnOnce() -> bool) -> bool {
    if !c.crc_recovery && c.warm_node_log { return true; }
    if c.appending && c.next_seg_free && !c.cp_disabled { return true; }
    !need_ssr()
}

/// Where the search for a free segment starts.
///
/// From the beginning of the main area for the logs whose blocks are expected
/// to be rewritten soon — the hot data log and every node log — so those
/// segments cluster at the low end and the cleaner finds them together. From
/// the beginning as well when the mount asked to reuse freed space, which is
/// exactly what a search from zero finds first. Otherwise from the segment
/// being closed, so consecutive allocations walk forward instead of contending
/// for the lowest free segment.
/// # C: O(1)
pub fn next_segno_hint(rewritten_soon: bool, reuse: bool, closing: u32) -> u32 {
    if rewritten_soon || reuse { return 0; }
    closing
}
