// The pathname column of `/proc/<pid>/maps` for an anonymous VMA.
//
// Linux `get_vma_name` fixes the precedence, and it is not obvious: the
// initial heap wins, then the initial stack, and only then the name
// `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME)` attached. `/proc/self/maps` and
// `/proc/<pid>/maps` are the same file rendered through two code paths here,
// so the decision lives in ONE place rather than being written twice and
// drifting — which it had: the self/ renderer emitted `[stack]` before it ever
// looked at the anon name, dropping the name for a growsdown VMA, while the
// pid renderer emitted the name and no `[stack]` or `[heap]` at all.
//
// Ungated: both consumers are kernel-target-only, where a `#[cfg(test)]` block
// would compile away in silence.

/// Which pseudo-tag the pathname column carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaTag {
    /// `vma_is_initial_heap` — the anonymous VMA covering `brk`.
    Heap,
    /// `vma_is_initial_stack` — the VMA containing the initial stack pointer.
    Stack,
    /// `[anon:NAME]` from `prctl(PR_SET_VMA_ANON_NAME)`.
    AnonName,
    /// No tag; the column is empty.
    None,
}

/// The facts `get_vma_name` decides from, for an anonymous VMA.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmaFacts {
    /// `vma_is_initial_heap(vma)`.
    pub initial_heap: bool,
    /// `vma_is_initial_stack(vma)`.
    pub initial_stack: bool,
    /// The VMA carries an `anon_vma_name`.
    pub has_anon_name: bool,
}

/// Linux `get_vma_name` for a VMA with no backing file.
/// # C: O(1)
pub fn tag_for(f: VmaFacts) -> VmaTag {
    if f.initial_heap { return VmaTag::Heap; }
    if f.initial_stack { return VmaTag::Stack; }
    if f.has_anon_name { return VmaTag::AnonName; }
    VmaTag::None
}

/// `vma_is_initial_heap(vma)` — `vm_start < mm->brk && vm_end > mm->start_brk`.
///
/// Strict on both ends: a zero-sized or not-yet-grown heap has
/// `start_brk == brk`, and the comparison then excludes every VMA rather than
/// tagging the one that happens to touch the boundary.
/// # C: O(1)
pub fn is_initial_heap(start: u64, end: u64, start_brk: u64, brk: u64) -> bool {
    start < brk && end > start_brk
}

/// `vma_is_initial_stack(vma)` — `vm_start <= mm->start_stack &&
/// vm_end >= mm->start_stack`.
///
/// Note what this is NOT: a growsdown flag. Any thread stack allocated by
/// `pthread_create` is growsdown too, and tagging all of them `[stack]` would
/// both contradict Linux and hide every `PR_SET_VMA` name a threading runtime
/// attached to its own stacks.
/// # C: O(1)
pub fn is_initial_stack(start: u64, end: u64, start_stack: u64) -> bool {
    start_stack != 0 && start <= start_stack && end >= start_stack
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The precedence itself. `[heap]` and `[stack]` outrank a caller-supplied
    /// name; a name outranks nothing at all.
    #[test]
    fn heap_beats_stack_beats_anon_name() {
        assert_eq!(tag_for(VmaFacts { initial_heap: true, initial_stack: true,
                                      has_anon_name: true }), VmaTag::Heap);
        assert_eq!(tag_for(VmaFacts { initial_stack: true, has_anon_name: true,
                                      ..VmaFacts::default() }), VmaTag::Stack);
        assert_eq!(tag_for(VmaFacts { has_anon_name: true, ..VmaFacts::default() }),
                   VmaTag::AnonName);
        assert_eq!(tag_for(VmaFacts::default()), VmaTag::None);
    }

    /// The bug this module exists to stop: a name on an ordinary anonymous
    /// mapping must reach the pathname column. A renderer that tested a
    /// growsdown flag first dropped it.
    #[test]
    fn a_named_ordinary_mapping_renders_its_name() {
        assert_eq!(tag_for(VmaFacts { has_anon_name: true, ..VmaFacts::default() }),
                   VmaTag::AnonName);
    }

    #[test]
    fn initial_stack_is_the_vma_containing_the_stack_pointer() {
        assert!(is_initial_stack(0x7fff_0000, 0x8000_0000, 0x7fff_f000));
        assert!(is_initial_stack(0x7fff_f000, 0x7fff_f000, 0x7fff_f000));
        // A different thread's stack does not contain the initial one.
        assert!(!is_initial_stack(0x1000_0000, 0x1001_0000, 0x7fff_f000));
        // An unknown stack pointer tags nothing rather than tagging the VMA
        // that happens to start at zero.
        assert!(!is_initial_stack(0, 0x1000, 0));
    }

    #[test]
    fn initial_heap_spans_the_break() {
        // start_brk .. brk grown to 0x2000.
        assert!(is_initial_heap(0x1000, 0x2000, 0x1000, 0x2000));
        // Entirely below start_brk.
        assert!(!is_initial_heap(0x0, 0x1000, 0x1000, 0x2000));
        // Entirely at or above brk.
        assert!(!is_initial_heap(0x2000, 0x3000, 0x1000, 0x2000));
    }

    /// An un-grown heap (`start_brk == brk`) tags nothing — the comparison is
    /// strict at both ends, so no VMA can satisfy it.
    #[test]
    fn an_ungrown_heap_tags_nothing() {
        assert!(!is_initial_heap(0x1000, 0x2000, 0x1000, 0x1000));
    }
}
