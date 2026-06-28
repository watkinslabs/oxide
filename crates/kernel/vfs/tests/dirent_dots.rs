//! dot-entry synthesis (`16§`/Linux `dir_emit_dots`, `fs/libfs.c`): every
//! directory's `readdir` stream must lead with "." (self ino, `DT_DIR`) then
//! ".." (parent ino, `DT_DIR`) before any real child, at fixed readdir cursors
//! `0` and `1`. The filesystem ROOT's ".." points back at the root itself
//! (`parent_ino == self_ino`). Without these synthetic records `getcwd(3)`
//! (which `..`-walks comparing inos), `find`, and `ls -ai` break. Driven over
//! the pure `emit_dots` helper — no QEMU, no global state, so no serial guard.

use vfs::dirent::{emit_dots, dtype_from_file_type, DOTS_RESERVED, DT_DIR};
use vfs::FileType;

/// One record the readdir fill callback saw: (d_ino, next_off, name, type).
#[derive(Debug, PartialEq, Eq)]
struct Seen { ino: u64, next_off: u64, name: String, ft: FileType }

/// Run `emit_dots` capturing every record the callback received. `stop_after`
/// caps how many records the callback accepts (returns `false` afterward) to
/// model a full user buffer; `usize::MAX` accepts all.
fn run(off: u64, self_ino: u64, parent_ino: u64, stop_after: usize) -> (bool, Vec<Seen>) {
    let mut seen = Vec::new();
    let completed = emit_dots(off, self_ino, parent_ino, &mut |ino, next_off, name, ft| {
        if seen.len() >= stop_after { return false; }
        seen.push(Seen { ino, next_off, name: name.to_string(), ft });
        true
    });
    (completed, seen)
}

/// From cursor 0 a non-root directory emits "." (self ino) then ".." (parent
/// ino), both `DT_DIR`, in that order, advancing the cursor 0→1→2.
#[test]
fn non_root_emits_dot_then_dotdot() {
    let (done, seen) = run(0, 42, 7, usize::MAX);
    assert!(done, "both dots fit → caller proceeds to real children");
    assert_eq!(seen.len(), 2, "exactly two synthetic records");

    assert_eq!(seen[0], Seen { ino: 42, next_off: 1, name: ".".into(), ft: FileType::Directory });
    assert_eq!(seen[1], Seen { ino: 7,  next_off: DOTS_RESERVED, name: "..".into(), ft: FileType::Directory });

    // The d_type byte each record packs is DT_DIR for both dots.
    assert_eq!(dtype_from_file_type(seen[0].ft), DT_DIR);
    assert_eq!(dtype_from_file_type(seen[1].ft), DT_DIR);
}

/// The filesystem ROOT: ".." resolves back to the root itself, so its d_ino
/// equals the root's own ino (Linux makes the root its own parent).
#[test]
fn root_dotdot_points_at_self() {
    let root_ino = 2; // ext2/4 root inode number, but value is irrelevant here
    let (done, seen) = run(0, root_ino, root_ino, usize::MAX);
    assert!(done);
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].ino, root_ino, "'.' is self");
    assert_eq!(seen[1].ino, root_ino, "'..' of root is root itself");
    assert_eq!(seen[1].name, "..");
}

/// Cursor 1 means "." was already consumed on a prior getdents page; only ".."
/// is emitted, advancing the cursor 1→2.
#[test]
fn cursor_one_resumes_at_dotdot_only() {
    let (done, seen) = run(1, 42, 7, usize::MAX);
    assert!(done);
    assert_eq!(seen.len(), 1, "only '..' remains");
    assert_eq!(seen[0], Seen { ino: 7, next_off: DOTS_RESERVED, name: "..".into(), ft: FileType::Directory });
}

/// Once the cursor is at or past `DOTS_RESERVED` both dots are done: nothing is
/// emitted and the caller is told to proceed straight to real children.
#[test]
fn cursor_past_dots_emits_nothing() {
    for off in [DOTS_RESERVED, 3, 10, 1_000] {
        let (done, seen) = run(off, 42, 7, usize::MAX);
        assert!(done, "no dots pending → proceed to children");
        assert!(seen.is_empty(), "cursor {off} past dots emits no synthetic record");
    }
}

/// Buffer full on the very first record: "." is attempted, the callback
/// refuses, `emit_dots` reports a stop and ".." is NOT emitted. The caller must
/// not advance into real children — the dot is retried next page.
#[test]
fn stop_on_dot_halts_before_dotdot() {
    let (done, seen) = run(0, 42, 7, 0);
    assert!(!done, "callback refused → caller stops, dot retried next page");
    assert!(seen.is_empty());
}

/// Buffer fills after "." but before "..": exactly one record emitted, stop
/// reported. The next page (cursor 1) resumes at "..".
#[test]
fn stop_after_dot_halts_before_dotdot() {
    let (done, seen) = run(0, 42, 7, 1);
    assert!(!done, "second dot did not fit");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].name, ".");
    assert_eq!(seen[0].next_off, 1, "resume cursor lands at '..'");
}

/// Real-child cookies in a dots-aware readdir begin at `DOTS_RESERVED`: the
/// cursor handed to child iteration is `off - DOTS_RESERVED`, so child 0 sits
/// at cursor `DOTS_RESERVED`, never colliding with a dot.
#[test]
fn child_cursors_begin_after_reserved_dots() {
    assert_eq!(DOTS_RESERVED, 2, "two dots reserve cursors 0 and 1");
    // A caller resuming at cursor DOTS_RESERVED skips zero children.
    assert_eq!(DOTS_RESERVED.saturating_sub(DOTS_RESERVED), 0);
    // Resuming at cursor 5 skips 3 children (5 - 2).
    assert_eq!(5u64.saturating_sub(DOTS_RESERVED), 3);
}
