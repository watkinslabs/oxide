// Flattened blob → the directory/file shape `/sys/firmware/devicetree` has to
// present (and, through the `/proc/device-tree` symlink, the older procfs
// ABI). Pure: it emits (path, kind, bytes) entries and never touches a
// filesystem, so the naming rules below are hosted-testable on a fixture blob.
//
// Naming rules, which are ABI:
//   * the root node's directory is literally `base`, hung under the
//     `devicetree` kset — every other node's directory is its unit name;
//   * each property becomes a file whose body is the property's RAW
//     big-endian bytes, no interpretation;
//   * a name that collides with one already used inside the same parent gets
//     `#1`, `#2`, … appended, up to 16 tries;
//   * a property whose name starts with `security-` is root-only and its body
//     is withheld (advertised size 0) — that is deliberate, not an omission.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::header::DtbError;
use crate::uapi::{OF_ROOT_DIR, OF_SECURE_PREFIX};
use crate::walk::{walk, Event, Flow};

/// Most `#N` disambiguation attempts before a colliding name is used as-is.
pub const OF_SAFE_NAME_TRIES: u32 = 16;

/// One exported node directory or property file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OfEntry<'a> {
    /// A node's directory, at `path`.
    Dir { path: String },
    /// A property file. `data` is the raw property value; `secure` marks the
    /// `security-` class whose body must not be served.
    Prop { path: String, data: &'a [u8], secure: bool },
}

impl OfEntry<'_> {
    /// Path this entry occupies. # C: O(1)
    pub fn path(&self) -> &str {
        match self { OfEntry::Dir { path } => path, OfEntry::Prop { path, .. } => path }
    }
}

/// Per-node record: its own path plus every child name already taken inside it.
/// Node directories and property files share one namespace, exactly as they
/// share one directory.
struct Level { path: String, used: Vec<String> }

/// Walk `blob` and emit every node directory and property file that belongs
/// under `kset_path` (e.g. `/sys/firmware/devicetree`). The root node's
/// directory is emitted first, so a consumer that registers entries in order
/// never creates a child before its parent.
///
/// Fails on a malformed blob, on a node or property name that is not UTF-8, or
/// on a name containing `/` — none of which a spec-conforming device tree
/// produces, and each of which would otherwise mint a path that does not mean
/// what it says.
/// # C: O(struct_block_size * max_children)
pub fn export_tree<'a, F>(blob: &'a [u8], kset_path: &str, mut f: F) -> Result<(), DtbError>
where F: FnMut(OfEntry<'a>) {
    let mut stack: Vec<Level> = Vec::new();
    let mut root = Level { path: kset_path.to_string(), used: Vec::new() };
    let mut err: Option<DtbError> = None;
    let res = walk(blob, |ev| {
        match ev {
            Event::BeginNode { name, depth } => {
                let raw = match node_name(name, depth) { Ok(n) => n, Err(e) => { err = Some(e); return Flow::Stop; } };
                let parent = stack.last_mut().unwrap_or(&mut root);
                let picked = safe_name(&mut parent.used, &raw);
                let path = join(&parent.path, &picked);
                f(OfEntry::Dir { path: path.clone() });
                stack.push(Level { path, used: Vec::new() });
            }
            Event::EndNode { .. } => { stack.pop(); }
            Event::Prop { name, data, .. } => {
                let raw = match utf8_name(name) { Ok(n) => n, Err(e) => { err = Some(e); return Flow::Stop; } };
                let secure = name.starts_with(OF_SECURE_PREFIX);
                let Some(node) = stack.last_mut() else { err = Some(DtbError::Inval); return Flow::Stop; };
                let picked = safe_name(&mut node.used, &raw);
                let path = join(&node.path, &picked);
                f(OfEntry::Prop { path, data, secure });
            }
        }
        Flow::Continue
    });
    if let Some(e) = err { return Err(e); }
    res
}

/// Directory name for a node: the root node is `base`, every other node keeps
/// its unit name.
fn node_name(name: &[u8], depth: u32) -> Result<String, DtbError> {
    if depth == 0 { return Ok(OF_ROOT_DIR.to_string()); }
    utf8_name(name)
}

/// A name usable as one path component. Rejects non-UTF-8, empty, `/`, and the
/// two dot names, all of which would resolve to something other than
/// themselves once joined into a path.
fn utf8_name(name: &[u8]) -> Result<String, DtbError> {
    let s = core::str::from_utf8(name).map_err(|_| DtbError::Inval)?;
    if s.is_empty() || s.contains('/') || s == "." || s == ".." { return Err(DtbError::Inval); }
    Ok(s.to_string())
}

/// `raw` if unused inside this parent, else `raw#1`, `raw#2`, … Records the
/// chosen name. After `OF_SAFE_NAME_TRIES` failures the last candidate is
/// returned regardless, rather than looping forever.
fn safe_name(used: &mut Vec<String>, raw: &str) -> String {
    if !used.iter().any(|u| u == raw) { used.push(raw.to_string()); return raw.to_string(); }
    let mut i = 1u32;
    loop {
        let cand = format!("{raw}#{i}");
        if !used.iter().any(|u| *u == cand) || i >= OF_SAFE_NAME_TRIES {
            used.push(cand.clone());
            return cand;
        }
        i += 1;
    }
}

/// `parent/child`, tolerating a parent that already ends in `/`.
fn join(parent: &str, child: &str) -> String {
    if parent.ends_with('/') { format!("{parent}{child}") } else { format!("{parent}/{child}") }
}
