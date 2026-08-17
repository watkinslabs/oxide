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

/// The order the types are searched in for a segment to recycle.
///
/// The log's OWN type first, because a segment already holding blocks of this
/// temperature is the one where a recycled write costs the cleaner nothing
/// extra: mixing a hot block into a cold segment is what makes a section
/// expensive to reclaim later, since the cleaner has to move the whole of it for
/// the sake of the one block that keeps changing.
///
/// Then the rest of the log's own CLASS — never across it, so a file's data is
/// never written into a segment holding node blocks — walked from the far end
/// towards this type: a warm or cold log looks at the coldest first and a hot log
/// at the hottest, so the search moves AWAY from the temperature that would
/// contaminate the segment it lands in.
/// # C: O(1)
/// The two logs beyond the persisted six — the pinned log and the
/// age-threshold one — are cold DATA by temperature, which is the type the
/// reference gives the age-threshold log when it asks for a victim.
pub fn victim_type_order(seg_type: usize) -> [usize; TYPES_PER_CLASS] {
    let ty = if seg_type >= NR_CURSEG_PERSIST_TYPE { COLD_DATA } else { seg_type };
    let node = ty >= NR_CURSEG_DATA_TYPE;
    let base = if node { NR_CURSEG_DATA_TYPE } else { 0 };
    // WARM and COLD walk down from the coldest; HOT walks up from itself.
    let reversed = ty >= base + 1;
    let mut out = [ty; TYPES_PER_CLASS];
    let mut at = 1;
    for i in 0..TYPES_PER_CLASS {
        let cand = if reversed { base + TYPES_PER_CLASS - 1 - i } else { base + i };
        if cand == ty { continue; }
        out[at] = cand;
        at += 1;
    }
    out
}

/// Logs one class holds: hot, warm and cold.
pub const TYPES_PER_CLASS: usize = 3;

/// Where the node logs begin, which is where the data class ends.
const NR_CURSEG_DATA_TYPE: usize = 3;

/// Logs that name a type the medium's segment table records.
const NR_CURSEG_PERSIST_TYPE: usize = NR_CURSEG_DATA_TYPE + TYPES_PER_CLASS;

/// The coldest data log, which is what a log outside the persisted six counts
/// as.
const COLD_DATA: usize = 2;

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
