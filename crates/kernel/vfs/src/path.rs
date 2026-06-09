// Path component splitter per `16§3`. Mirrors POSIX semantics:
// repeated `/` collapse, leading `/` ⇒ absolute, trailing `/` is
// ignored, `.` is dropped, `..` walks up (the caller decides what
// "up" means at the root or at a mount boundary).
//
// Symlink resolution + RESOLVE_BENEATH / RESOLVE_NO_SYMLINKS / mount
// crossing all live in the future `path_lookup` (`16§3`); this module
// only does the lexical split.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Component<'a> {
    Root,
    Normal(&'a str),
    ParentDir, // ..
}

/// Split `path` into components per POSIX. Empty or `.`-only segments
/// are skipped.
/// # C: O(len)
pub fn components(path: &str) -> Vec<Component<'_>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    if path.starts_with('/') {
        out.push(Component::Root);
    }
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' {
            if start < i {
                push_segment(&mut out, &path[start..i]);
            }
            i += 1;
            start = i;
        } else {
            i += 1;
        }
    }
    if start < bytes.len() {
        push_segment(&mut out, &path[start..]);
    }
    out
}

fn push_segment<'a>(out: &mut Vec<Component<'a>>, seg: &'a str) {
    match seg {
        "" | "."   => {} // skip
        ".."       => out.push(Component::ParentDir),
        s          => out.push(Component::Normal(s)),
    }
}

/// True iff `path` is absolute (begins with `/`).
/// # C: O(1)
pub fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// Trim trailing newlines + NULs from a hostname-shaped byte slice
/// and clamp to `max`. Used by the global hostname slot per
/// `28§4` / sethostname(2). `echo "host" > /proc/sys/kernel/hostname`
/// passes a trailing newline that must be stripped.
/// # C: O(N)
pub fn trim_hostname<'a>(input: &'a [u8], max: usize) -> &'a [u8] {
    let mut end = input.len().min(max);
    while end > 0 && matches!(input[end - 1], b'\n' | 0) { end -= 1; }
    &input[..end]
}

/// Resolve `path` against `cwd`. If `path` is absolute, returns
/// the lexically-normalized form. Otherwise joins as `cwd/path`
/// then normalizes. `cwd` must itself be absolute.
/// # C: O(len)
pub fn resolve_against_cwd(cwd: &str, path: &str) -> Option<String> {
    if is_absolute(path) {
        return lexical_normalize(path);
    }
    let mut joined = String::with_capacity(cwd.len() + 1 + path.len());
    joined.push_str(cwd);
    if !cwd.ends_with('/') { joined.push('/'); }
    joined.push_str(path);
    lexical_normalize(&joined)
}

/// Parse `/proc/{self|<pid>}/fd/<n>` → `(tid_opt, fd)` (`self` ⇒
/// `None`). The Linux magic-fd-link reopen/readlink contract: opening
/// or stat-ing this path acts on the open file description fd `<n>`
/// already holds. Returns `None` when the shape doesn't match.
/// # C: O(N_path)
pub fn parse_proc_fd(path: &str) -> Option<(Option<u32>, i32)> {
    let rest = path.strip_prefix("/proc/")?;
    let mut it = rest.splitn(3, '/');
    let who = it.next()?;
    if it.next()? != "fd" { return None; }
    let fd: i32 = it.next()?.parse().ok()?;
    let tid = if who == "self" { None } else { Some(who.parse::<u32>().ok()?) };
    Some((tid, fd))
}

/// Map any path that resolves by **duplicating an existing open file
/// description** → `(tid_opt, fd)`. The Linux fd-link open family:
/// `/dev/std{in,out,err}` (fd 0/1/2), `/dev/fd/<n>`, and
/// `/proc/{self|<pid>}/fd/<n>`. `None` otherwise (resolve normally).
/// # C: O(N_path)
pub fn dup_fd_target(path: &str) -> Option<(Option<u32>, i32)> {
    match path {
        "/dev/stdin"  => return Some((None, 0)),
        "/dev/stdout" => return Some((None, 1)),
        "/dev/stderr" => return Some((None, 2)),
        _ => {}
    }
    if let Some(rest) = path.strip_prefix("/dev/fd/") {
        return rest.parse::<i32>().ok().map(|n| (None, n));
    }
    parse_proc_fd(path)
}

/// Normalize a path lexically (resolve `..` and `.` against an
/// absolute prefix). Does NOT consult the FS. Returns `None` if a
/// `..` would escape the root.
/// # C: O(len)
pub fn lexical_normalize(path: &str) -> Option<String> {
    let mut stack: Vec<&str> = Vec::new();
    let abs = is_absolute(path);
    for c in components(path) {
        match c {
            Component::Root      => {} // absolute already implied; ignore
            Component::Normal(s) => stack.push(s),
            Component::ParentDir => {
                if stack.pop().is_none() && abs {
                    return None;
                }
            }
        }
    }
    let mut out = String::new();
    if abs { out.push('/'); }
    for (i, s) in stack.iter().enumerate() {
        if i > 0 { out.push('/'); }
        out.push_str(s);
    }
    if out.is_empty() { out.push('.'); }
    Some(out)
}
