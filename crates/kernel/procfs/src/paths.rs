// Pure-string path parsers for procfs lookups per `19§4`. Kept in
// the procfs crate so they're hosted-testable; kernel/src/procfs.rs
// dispatches inode construction off the parsed shape.

/// Parsed shape of a `/proc/...` path. Only covers the dynamic
/// per-pid surface; static `/proc/<file>` lookups go through the
/// flat devfs registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcPath<'a> {
    /// `/proc/self`
    SelfDir,
    /// `/proc/self/<rest>` (multi-segment leaf — caller resolves)
    SelfChild(&'a str),
    /// `/proc/<tid>`
    PidDir(u32),
    /// `/proc/<tid>/<rest>`
    PidChild(u32, &'a str),
    /// Not under `/proc/` or empty.
    NotProc,
}

/// Parse a `/proc/...` path. Returns `NotProc` for paths that don't
/// match the procfs prefix or have no head segment.
/// # C: O(path.len())
pub fn parse_proc_path(path: &str) -> ProcPath<'_> {
    let rest = match path.strip_prefix("/proc/") {
        Some(r) => r,
        None    => return ProcPath::NotProc,
    };
    if rest.is_empty() { return ProcPath::NotProc; }
    let (head, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None    => (rest, None),
    };
    if head == "self" {
        return match tail {
            None         => ProcPath::SelfDir,
            Some(t) if t.is_empty() => ProcPath::SelfDir,
            Some(t)      => ProcPath::SelfChild(t),
        };
    }
    let tid: u32 = match head.parse() {
        Ok(t)  => t,
        Err(_) => return ProcPath::NotProc,
    };
    match tail {
        None         => ProcPath::PidDir(tid),
        Some(t) if t.is_empty() => ProcPath::PidDir(tid),
        Some(t)      => ProcPath::PidChild(tid, t),
    }
}

/// Filter for synthetic-directory readdir: returns Some(leaf_name)
/// when `path` is exactly `<prefix>/<single-segment>`. Used by the
/// devfs `PrefixDirInode` and analogous tmpfs/procfs readers.
///
/// `prefix` may be `"/"`, in which case any non-empty single-segment
/// child of `/` matches. For other prefixes, `path` must start with
/// `<prefix>/` and the remainder must contain no further `/`.
/// # C: O(path.len())
pub fn child_under<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    if prefix == "/" {
        let leaf = path.strip_prefix('/')?;
        if leaf.is_empty() || leaf.contains('/') { return None; }
        return Some(leaf);
    }
    let rest = path.strip_prefix(prefix)?.strip_prefix('/')?;
    if rest.is_empty() || rest.contains('/') { return None; }
    Some(rest)
}
