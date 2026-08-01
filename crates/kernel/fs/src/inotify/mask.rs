// Per-mark MASK APPLICABILITY — whether one mark's event mask (or ignore mask)
// covers a particular notification, given what the notification is about and
// how the mark reached it.
//
// Deliberately free of any target gate so every arm is hosted-testable;
// `dispatch.rs` only sequences these predicates (docs/53).

use crate::inotify::types::{FAN_EVENT_ON_CHILD, FAN_ONDIR};

/// How a mark was reached by one notification. The distinction is not
/// cosmetic: a mark on a directory sees events about the directory ITSELF and
/// events about entries INSIDE it, and only the second kind is gated on the
/// mark having asked for child events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IterType {
    /// The mark is on the object the event happened to.
    Self_,
    /// The mark is on the PARENT directory of the object the event happened to.
    Parent,
    /// The mark is on the mount the object is reached through.
    Mount,
    /// The mark is on the object's whole filesystem.
    Filesystem,
}

/// Linux `fsnotify_mask_applicable`: does `mask` cover this notification?
///
/// Two independent gates:
///   * an event about a DIRECTORY requires `FAN_ONDIR` in the mask — a watcher
///     that did not ask for directory events does not get them;
///   * an event reached through a mark on the PARENT requires
///     `FAN_EVENT_ON_CHILD`. Without this leg a fanotify mark on a directory
///     receives every open/read/write of every file inside it, which is not
///     what the mark asked for and is a large amount of traffic.
/// # C: O(1)
pub(crate) fn mask_applicable(mask: u32, is_dir: bool, iter: IterType) -> bool {
    if is_dir && (mask & FAN_ONDIR) == 0 { return false; }
    if iter == IterType::Parent && (mask & FAN_EVENT_ON_CHILD) == 0 { return false; }
    true
}

/// Linux `fsnotify_ignore_mask`: the ignore mask a mark presents, once the
/// legacy/modern distinction is applied.
///
/// `FAN_MARK_IGNORE` (modern) stores exactly what the caller asked to ignore,
/// event flags included. `FAN_MARK_IGNORED_MASK` (legacy) predates those flags
/// having meaning in an ignore mask, so the stored set is reinterpreted:
/// directory events are always ignored, and child events are ignored only when
/// the mark is watching children in the first place.
/// # C: O(1)
pub(crate) fn ignore_mask(stored: u32, mark_mask: u32, has_ignore_flags: bool) -> u32 {
    if has_ignore_flags { return stored; }
    let mut m = stored | FAN_ONDIR;
    m &= !FAN_EVENT_ON_CHILD;
    m |= mark_mask & FAN_EVENT_ON_CHILD;
    m
}

/// Linux `fsnotify_effective_ignore_mask`: the ignore mask that actually
/// applies to one notification. An empty stored set ignores nothing; for an
/// event that is neither about a directory nor reached through a parent the
/// stored set applies verbatim; otherwise the ignore mask must itself be
/// applicable, or it ignores nothing at all.
/// # C: O(1)
pub(crate) fn effective_ignore_mask(stored: u32, mark_mask: u32, has_ignore_flags: bool,
                                    is_dir: bool, iter: IterType) -> u32 {
    if stored == 0 { return 0; }
    if !is_dir && iter != IterType::Parent { return stored; }
    let m = ignore_mask(stored, mark_mask, has_ignore_flags);
    if !mask_applicable(m, is_dir, iter) { return 0; }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inotify::types::{FAN_CREATE, FAN_MODIFY, FAN_OPEN};

    /// A directory event needs FAN_ONDIR; a file event does not. # C: O(1)
    #[test]
    fn ondir_gates_only_directory_events() {
        assert!(mask_applicable(FAN_OPEN, false, IterType::Self_));
        assert!(!mask_applicable(FAN_OPEN, true, IterType::Self_));
        assert!(mask_applicable(FAN_OPEN | FAN_ONDIR, true, IterType::Self_));
    }

    /// A mark reached through the PARENT needs FAN_EVENT_ON_CHILD — this is the
    /// leg that stops a bare fanotify directory mark from seeing every access
    /// to every file inside it. # C: O(1)
    #[test]
    fn a_parent_mark_needs_event_on_child() {
        assert!(!mask_applicable(FAN_OPEN, false, IterType::Parent));
        assert!(mask_applicable(FAN_OPEN | FAN_EVENT_ON_CHILD, false, IterType::Parent));
        // Mount and filesystem marks are not parent marks and are not gated.
        assert!(mask_applicable(FAN_OPEN, false, IterType::Mount));
        assert!(mask_applicable(FAN_OPEN, false, IterType::Filesystem));
    }

    /// Both gates apply at once: a child DIRECTORY event needs both bits.
    /// # C: O(1)
    #[test]
    fn both_gates_apply_together() {
        assert!(!mask_applicable(FAN_CREATE | FAN_EVENT_ON_CHILD, true, IterType::Parent));
        assert!(!mask_applicable(FAN_CREATE | FAN_ONDIR, true, IterType::Parent));
        assert!(mask_applicable(FAN_CREATE | FAN_ONDIR | FAN_EVENT_ON_CHILD, true, IterType::Parent));
    }

    /// Legacy ignore masks always ignore directory events and inherit the
    /// mark's own child-watching decision. # C: O(1)
    #[test]
    fn legacy_ignore_mask_is_reinterpreted() {
        assert_eq!(ignore_mask(FAN_MODIFY, FAN_OPEN, false), FAN_MODIFY | FAN_ONDIR);
        assert_eq!(ignore_mask(FAN_MODIFY, FAN_OPEN | FAN_EVENT_ON_CHILD, false),
                   FAN_MODIFY | FAN_ONDIR | FAN_EVENT_ON_CHILD);
        // A legacy caller's own ON_CHILD bit is discarded and re-derived.
        assert_eq!(ignore_mask(FAN_MODIFY | FAN_EVENT_ON_CHILD, FAN_OPEN, false),
                   FAN_MODIFY | FAN_ONDIR);
    }

    /// A modern ignore mask is stored and used verbatim. # C: O(1)
    #[test]
    fn modern_ignore_mask_is_verbatim() {
        assert_eq!(ignore_mask(FAN_MODIFY, FAN_OPEN | FAN_EVENT_ON_CHILD, true), FAN_MODIFY);
        assert_eq!(ignore_mask(FAN_MODIFY | FAN_ONDIR, FAN_OPEN, true), FAN_MODIFY | FAN_ONDIR);
    }

    /// Nothing stored ignores nothing, whatever the event looks like. # C: O(1)
    #[test]
    fn an_empty_ignore_set_ignores_nothing() {
        assert_eq!(effective_ignore_mask(0, FAN_OPEN, false, true, IterType::Parent), 0);
    }

    /// A plain file event on a self/mount/fs mark uses the stored set directly
    /// without consulting the event flags at all. # C: O(1)
    #[test]
    fn a_plain_file_event_uses_the_stored_set() {
        assert_eq!(effective_ignore_mask(FAN_MODIFY, 0, false, false, IterType::Self_), FAN_MODIFY);
        assert_eq!(effective_ignore_mask(FAN_MODIFY, 0, false, false, IterType::Mount), FAN_MODIFY);
    }

    /// A modern ignore mask that did not ask for child events ignores nothing
    /// on the parent leg — the suppression does not silently leak onto
    /// children. # C: O(1)
    #[test]
    fn a_modern_ignore_mask_without_on_child_does_not_cover_children() {
        assert_eq!(effective_ignore_mask(FAN_MODIFY, FAN_MODIFY, true, false, IterType::Parent), 0);
        assert_eq!(effective_ignore_mask(FAN_MODIFY | FAN_EVENT_ON_CHILD, FAN_MODIFY, true,
                                         false, IterType::Parent),
                   FAN_MODIFY | FAN_EVENT_ON_CHILD);
    }

    /// A legacy ignore mask on a child-watching mark DOES cover children,
    /// because the reinterpretation copies the mark's own ON_CHILD bit in.
    /// # C: O(1)
    #[test]
    fn a_legacy_ignore_mask_follows_the_marks_child_decision() {
        assert_eq!(effective_ignore_mask(FAN_MODIFY, FAN_MODIFY, false, false, IterType::Parent), 0);
        assert_eq!(effective_ignore_mask(FAN_MODIFY, FAN_MODIFY | FAN_EVENT_ON_CHILD, false,
                                         false, IterType::Parent),
                   FAN_MODIFY | FAN_ONDIR | FAN_EVENT_ON_CHILD);
    }

    /// A legacy ignore mask always covers directory events, since the
    /// reinterpretation forces FAN_ONDIR on. # C: O(1)
    #[test]
    fn a_legacy_ignore_mask_always_covers_directory_events() {
        assert_eq!(effective_ignore_mask(FAN_CREATE, FAN_CREATE, false, true, IterType::Self_),
                   FAN_CREATE | FAN_ONDIR);
        // The modern form does not, unless it said so.
        assert_eq!(effective_ignore_mask(FAN_CREATE, FAN_CREATE, true, true, IterType::Self_), 0);
    }
}
