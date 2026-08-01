// Cookie-ordered readdir for the SYNTHESIZED procfs / sysfs directories.
//
// None of these directories stores a child list: /proc's pid set,
// /proc/<pid>/task, /proc/<pid>/fd, /proc/<pid>/fdinfo and
// /sys/devices/system/cpu are re-derived from live kernel state on every
// `getdents` call. An ordinal cursor over such a snapshot is not a `d_off`
// cookie — a task exiting or an fd closing between two pages shifts every later
// ordinal, so the listing duplicates or skips entries and a `seekdir(3)` cookie
// taken before the mutation names a different entry after it. The cookie space
// lives in `vfs::readdir_cookie`: a position derived from the NAME alone.
//
// Ungated on purpose. Every decision here — which names a directory holds,
// which `d_type` each takes, and that a name whose object vanished is dropped
// rather than emitted with `d_ino == 0` — is hosted-testable, while the
// `iterate` bodies that call it sit behind `cfg(target_os = "oxide-kernel")`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use vfs::{CookieEntry, DirContext, FileType, KResult};

/// `/proc/self` — magic symlink to the caller's own pid directory.
pub const PROC_SELF: &str = "self";
/// `/proc/thread-self` — magic symlink to the caller's own tid directory.
pub const PROC_THREAD_SELF: &str = "thread-self";

/// Decimal name of a numeric directory slot (a pid, tid or fd). # C: O(log v)
pub fn decimal_name(v: u32) -> String { format!("{v}") }

/// Names `/proc`'s root holds beyond its statically registered children: the
/// two magic symlinks, then one directory per live vpid.
///
/// `self` / `thread-self` are `S_IFLNK` (Linux `proc_self_inode_operations` —
/// they recompute their target on every `readlink`), so a listing must report
/// `DT_LNK` for them; reporting `DT_DIR` makes `find`/`ls -F` descend into a
/// link and double-count every process. # C: O(N_pids)
pub fn proc_root_dynamic(vpids: &[u32]) -> Vec<(String, FileType)> {
    let mut v: Vec<(String, FileType)> = Vec::with_capacity(vpids.len() + 2);
    v.push((String::from(PROC_SELF), FileType::Symlink));
    v.push((String::from(PROC_THREAD_SELF), FileType::Symlink));
    for p in vpids { v.push((decimal_name(*p), FileType::Directory)); }
    v
}

/// Append `names` to `out`, taking each entry's real inode number from
/// `resolve`.
///
/// A name whose object vanished between the snapshot and the resolve is NOT
/// listed: `d_ino == 0` is how a filesystem marks a deleted placeholder, so a
/// live entry must never carry it, and an entry that is gone must not appear at
/// all. # C: O(N)
pub fn push_resolved<F>(out: &mut Vec<CookieEntry>, names: impl IntoIterator<Item = (String, FileType)>, mut resolve: F)
where F: FnMut(&str) -> Option<u64>
{
    for (name, d_type) in names {
        let Some(ino) = resolve(&name) else { continue };
        out.push(CookieEntry::new(name, ino, d_type));
    }
}

/// [`push_resolved`] then [`vfs::emit_by_cookie`] — the whole body of a
/// synthesized directory's `iterate`. # C: O(N log N)
pub fn emit_resolved<F>(names: impl IntoIterator<Item = (String, FileType)>, resolve: F, ctx: &mut DirContext) -> KResult<()>
where F: FnMut(&str) -> Option<u64>
{
    let mut es: Vec<CookieEntry> = Vec::new();
    push_resolved(&mut es, names, resolve);
    vfs::emit_by_cookie(&mut es, ctx)
}

/// Pair each name in a static table with one `d_type`. # C: O(N)
pub fn typed(names: &[&str], d_type: FileType) -> Vec<(String, FileType)> {
    names.iter().map(|n| (String::from(*n), d_type)).collect()
}
