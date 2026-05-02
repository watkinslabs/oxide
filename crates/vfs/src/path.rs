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
