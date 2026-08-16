//! Section arithmetic, apart from any volume.
//!
//! A SECTION is the unit the cleaner chooses, so it is the unit a pinned file
//! is given: a section holding only pinned blocks is one the cleaner will
//! never pick, and one holding a mixture is one it can neither empty nor
//! leave alone. Everything here is about that distinction, and none of it
//! shows on a volume whose sections are one segment each — which is why it is
//! here, where the section width is a parameter rather than a fixture's
//! choice.

/// The first segment of the section `segno` belongs to. # C: O(1)
pub fn section_first(segno: u32, segs_per_sec: u32) -> u32 {
    let per = segs_per_sec.max(1);
    (segno / per) * per
}

/// Whether the section starting at `first` lies wholly inside the main area
/// and every one of its segments is free. # C: O(segments per section)
pub fn section_is_free(first: u32, segs_per_sec: u32, main_segs: u32,
                       free: impl Fn(u32) -> bool) -> bool {
    let per = segs_per_sec.max(1);
    if first % per != 0 { return false; }
    match first.checked_add(per) {
        Some(end) if end <= main_segs => (first..end).all(free),
        _ => false,
    }
}

/// The first wholly free section at or after the one `hint` falls in,
/// wrapping once.
///
/// A section, not a segment: taking the first free SEGMENT would put pinned
/// blocks in a section whose other segments the allocator is still free to
/// fill, and the cleaner would then be looking at a section it must not move
/// and cannot skip.
/// # C: O(main segments)
pub fn find_free_section(hint: u32, segs_per_sec: u32, main_segs: u32,
                         free: impl Fn(u32) -> bool + Copy) -> Option<u32> {
    let per = segs_per_sec.max(1);
    let sections = main_segs / per;
    if sections == 0 { return None; }
    let from = section_first(hint, per) / per;
    (0..sections)
        .map(|i| ((from + i) % sections) * per)
        .find(|&first| section_is_free(first, per, main_segs, free))
}

/// The next segment the pinned log rolls to inside the section it is already
/// in, or `None` at the section's end.
///
/// Rolling within the section is what keeps one file's pinned blocks in one
/// section; at the end there is no next segment here and a whole new section
/// has to be found.
/// # C: O(1)
pub fn next_in_section(old: u32, segs_per_sec: u32, main_segs: u32) -> Option<u32> {
    let per = segs_per_sec.max(1);
    let next = old.checked_add(1)?;
    if next % per == 0 || next >= main_segs { return None; }
    Some(next)
}
