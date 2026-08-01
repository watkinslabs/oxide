// fanotify RENAME events (`FAN_RENAME`) — the single record that names BOTH
// ends of a rename, and the two info-record types that carry them.
//
// The MOVED_FROM/MOVED_TO pair predates this and is still emitted: it pairs two
// records by a cookie, so a watcher has to hold state between reads and can
// lose half the pair to a queue overflow. `FAN_RENAME` is the answer — ONE
// event, reported on the SOURCE directory before either half of the pair, with
// the old parent+name and the new parent+name in two info records, and no
// cookie at all because there is nothing to pair with.
//
// Which halves a mark is told about depends on where the mark is:
//   * a mark on the whole filesystem sees the rename from both ends, so it gets
//     both parent+name records;
//   * a mark on the SOURCE directory gets the old parent+name;
//   * a mark on the DESTINATION directory gets the new parent+name — and only
//     that, since it never watched the source.
// A rename inside ONE directory satisfies both of the last two, and that mark
// gets both records.
//
// Deliberately free of any target gate so the half-selection and the record
// order are hosted-testable.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use vfs::{FileType, InodeRef};

use crate::inotify::dispatch::instances;
use crate::inotify::layout::encode_name;
use crate::inotify::mask::mask_applicable;
use crate::inotify::types::{inode_key, Event, MarkScope, Watch, FAN_ONDIR, FAN_RENAME,
    MARK_COUNT};

/// `FAN_EVENT_INFO_TYPE_OLD_DFID_NAME` — the SOURCE directory's fid plus the
/// entry's old name. A rename-specific type: a watcher must be able to tell the
/// two parent+name records apart, and the ordinary `DFID_NAME` type says only
/// "a directory and a name".
pub(crate) const FAN_EVENT_INFO_TYPE_OLD_DFID_NAME: u8 = 10;
/// `FAN_EVENT_INFO_TYPE_NEW_DFID_NAME` — the DESTINATION directory's fid plus
/// the entry's new name.
pub(crate) const FAN_EVENT_INFO_TYPE_NEW_DFID_NAME: u8 = 12;

/// Does this reported mask describe a rename? Such an event uses the two
/// rename-specific record types and never merges with anything that does not.
/// # C: O(1)
pub(crate) fn is_rename_event(mask: u32) -> bool { mask & FAN_RENAME != 0 }

/// Which halves of a rename one mark is told about, or `None` when it is told
/// nothing.
///
/// `on_old` / `on_new` are whether the mark covers the source and destination
/// directories. A filesystem-scope mark covers the rename as a whole and is
/// given both halves whichever end it matched through; an inode-scope mark is
/// given exactly the ends it is attached to. Mount- and mount-namespace-scope
/// marks cannot carry `FAN_RENAME` at all, so they are told nothing.
/// # C: O(1)
pub(crate) fn halves_for(scope: MarkScope, on_old: bool, on_new: bool) -> Option<(bool, bool)> {
    if !on_old && !on_new { return None; }
    match scope {
        MarkScope::Filesystem => Some((true, true)),
        MarkScope::Inode => Some((on_old, on_new)),
        MarkScope::Mount | MarkScope::MountNamespace => None,
    }
}

/// Does this mark report the rename at all, once its own mask, its ignore set
/// and the directory gate have been applied? # C: O(1)
fn rename_reported(w: &Watch, is_dir: bool) -> bool {
    let iter = w.iter_type();
    if w.mask & FAN_RENAME == 0 { return false; }
    if w.effective_ignore(is_dir, iter) & FAN_RENAME != 0 { return false; }
    mask_applicable(w.mask, is_dir, iter)
}

/// Report one rename as a single `FAN_RENAME` event carrying both ends.
///
/// Fired BEFORE the `MOVED_FROM`/`MOVED_TO` pair: a watcher that asked for both
/// forms reads the whole-rename record first, so it never has to hold a
/// half-rename while waiting to find out whether the complete one is coming.
/// # C: O(N_groups × N_watches)
pub(crate) fn fire_rename(old_parent: &InodeRef, new_parent: &InodeRef,
                          old_name: &str, new_name: &str, is_dir: bool) {
    if MARK_COUNT.load(Ordering::Acquire) == 0 { return; }
    let (okey, ofsid) = (inode_key(old_parent), old_parent.fsid());
    let (nkey, nfsid) = (inode_key(new_parent), new_parent.fsid());
    let g = instances().lock();
    for w in g.iter() {
        let Some(arc) = w.upgrade() else { continue };
        // `FAN_RENAME` is a fanotify-only event: inotify has no record shape
        // that could carry two parents and two names.
        if !arc.fanotify { continue; }
        let pid = crate::inotify::perm::reporting_pid(&arc);
        let ondir = if is_dir && arc.reports_event_flags() { FAN_ONDIR } else { 0 };
        let hits: Vec<(i32, bool, bool)> = {
            let watches = arc.watches.lock();
            watches.iter()
                .filter(|wi| rename_reported(wi, is_dir))
                .filter_map(|wi| {
                    let on_old = wi.applies(okey, ofsid);
                    let on_new = wi.applies(nkey, nfsid);
                    halves_for(wi.scope, on_old, on_new).map(|(o, n)| (wi.wd, o, n))
                })
                .collect()
        };
        for (wd, rep_old, rep_new) in hits {
            let ev = Event {
                wd,
                mask: FAN_RENAME | ondir,
                pid,
                // The old parent+name ride in the ordinary object/name pair, so
                // a mark told only about the destination reports the NEW parent
                // there instead and emits no old record at all.
                obj:  if rep_old { Some(old_parent.clone()) } else { None },
                name: if rep_old { encode_name(Some(old_name)) } else { Vec::new() },
                dir2: if rep_new { Some(new_parent.clone()) } else { None },
                name2: if rep_new { encode_name(Some(new_name)) } else { Vec::new() },
                ..Default::default()
            };
            arc.enqueue_event(ev);
        }
    }
}

/// `FS_ISDIR` for a rename: whether the object that moved is a directory. An
/// unresolvable object is not a directory, which is the same answer the
/// MOVED_FROM/MOVED_TO pair gives. # C: O(1)
pub(crate) fn moved_is_dir(moved: Option<&InodeRef>) -> bool {
    moved.map(|m| m.file_type() == FileType::Directory).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inotify::types::{FAN_CREATE, FAN_EVENT_ON_CHILD};

    /// A filesystem mark watches the rename as a whole and is told both ends
    /// whichever end it matched through. # C: O(1)
    #[test]
    fn a_filesystem_mark_is_told_both_ends() {
        assert_eq!(halves_for(MarkScope::Filesystem, true, true), Some((true, true)));
        assert_eq!(halves_for(MarkScope::Filesystem, true, false), Some((true, true)));
        assert_eq!(halves_for(MarkScope::Filesystem, false, true), Some((true, true)));
    }

    /// An inode mark is told exactly the ends it is attached to. # C: O(1)
    #[test]
    fn an_inode_mark_is_told_only_the_ends_it_watches() {
        assert_eq!(halves_for(MarkScope::Inode, true, false), Some((true, false)));
        assert_eq!(halves_for(MarkScope::Inode, false, true), Some((false, true)));
        assert_eq!(halves_for(MarkScope::Inode, true, true), Some((true, true)),
                   "a rename inside one directory names that directory twice");
    }

    /// A mark that covers neither end hears nothing; mount and mount-namespace
    /// marks hear nothing regardless, since neither may carry the event bit.
    /// # C: O(1)
    #[test]
    fn a_mark_covering_neither_end_or_of_the_wrong_scope_hears_nothing() {
        assert_eq!(halves_for(MarkScope::Inode, false, false), None);
        assert_eq!(halves_for(MarkScope::Filesystem, false, false), None);
        assert_eq!(halves_for(MarkScope::Mount, true, true), None);
        assert_eq!(halves_for(MarkScope::MountNamespace, true, true), None);
    }

    #[test]
    fn only_the_rename_bit_makes_a_rename_event() {
        assert!(is_rename_event(FAN_RENAME));
        assert!(!is_rename_event(FAN_CREATE));
        assert!(!is_rename_event(0));
    }

    /// The two record types are the rename-specific numbers, distinct from each
    /// other and from every ordinary fid type. # C: O(1)
    #[test]
    fn the_two_rename_record_types_are_distinct_reserved_numbers() {
        use crate::inotify::fan_layout::{FAN_EVENT_INFO_TYPE_DFID, FAN_EVENT_INFO_TYPE_DFID_NAME,
            FAN_EVENT_INFO_TYPE_FID};
        for t in [FAN_EVENT_INFO_TYPE_FID, FAN_EVENT_INFO_TYPE_DFID_NAME, FAN_EVENT_INFO_TYPE_DFID] {
            assert_ne!(t, FAN_EVENT_INFO_TYPE_OLD_DFID_NAME);
            assert_ne!(t, FAN_EVENT_INFO_TYPE_NEW_DFID_NAME);
        }
        assert_ne!(FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, FAN_EVENT_INFO_TYPE_NEW_DFID_NAME);
    }

    /// The directory gate applies: a mark without `FAN_ONDIR` is not told about
    /// a renamed DIRECTORY, and the child gate never applies — a rename is
    /// reported on the directory as an event about the directory itself.
    /// # C: O(1)
    #[test]
    fn a_directory_rename_needs_ondir_but_never_needs_on_child() {
        let mut w = Watch::new(1, 0, 0, 0, MarkScope::Inode, FAN_RENAME, 0, 0,
                               false, false, None);
        assert!(rename_reported(&w, false));
        assert!(!rename_reported(&w, true), "a renamed directory needs FAN_ONDIR");
        w.mask = FAN_RENAME | FAN_ONDIR;
        assert!(rename_reported(&w, true));
        w.mask = FAN_RENAME;
        w.ignored = FAN_RENAME;
        w.ignore_has_flags = true;
        assert!(!rename_reported(&w, false), "an ignored rename reports nothing");
        w.ignored = 0;
        w.mask = FAN_CREATE | FAN_EVENT_ON_CHILD;
        assert!(!rename_reported(&w, false), "a mark that did not ask for renames hears none");
    }
}
