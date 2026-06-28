//! namei-D27: the walk's component splitter now DELEGATES to the single
//! lexical classifier `path::components` (the duplicate
//! `split('/').filter(non-empty)` splitter is gone). These tests pin the
//! consolidated behaviour — `.`, `//`, and `..` segments are classified by
//! ONE splitter — and guard against future divergence. No behaviour change:
//! they pass before AND after the consolidation.

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, LookupFlags};

struct Dir { ino: u64, kids: BTreeMap<String, InodeRef> }
impl Inode for Dir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> vfs::KResult<InodeRef> {
        self.kids.get(name).cloned().ok_or(vfs::VfsError::Enoent)
    }
}

struct F { ino: u64 }
impl Inode for F {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<InodeRef> { Err(vfs::VfsError::Enotdir) }
}

fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    Arc::new(Dir { ino, kids: m })
}
fn file(ino: u64) -> InodeRef { Arc::new(F { ino }) }

// Tree:  / → a → b → f(file).  a (ino 10), a/b (ino 11), a/b/f (ino 12).
fn build_root() -> Arc<Dentry> {
    let f = file(12);
    let b = dir(11, &[("f", f)]);
    let a = dir(10, &[("b", b)]);
    Dentry::new_root(dir(2, &[("a", a)]))
}

fn ino_of(root: &Arc<Dentry>, path: &str) -> u64 {
    vfs::path_lookup(root.clone(), root.clone(), path, LookupFlags::default())
        .expect("resolve").0.ino()
}

// `/a/./b` == `/a/b` : the `.` segment is dropped by path::push_segment, not by
// a separate `if comp == "."` branch in the walk.
#[test]
fn dot_segment_is_skipped_by_one_splitter() {
    let root = build_root();
    assert_eq!(ino_of(&root, "/a/./b"), ino_of(&root, "/a/b"), ". skipped");
    assert_eq!(ino_of(&root, "/a/b"), 11);
}

// `/a//b` == `/a/b` : the empty segment between the doubled `/` is dropped.
#[test]
fn empty_segment_is_skipped_by_one_splitter() {
    let root = build_root();
    assert_eq!(ino_of(&root, "/a//b"), ino_of(&root, "/a/b"), "// collapsed");
}

// `/a/b/../b` == `/a/b` : `..` is preserved by the splitter and handled by the
// walk's follow_dotdot (steps up then back down).
#[test]
fn dotdot_segment_walks_up_then_back() {
    let root = build_root();
    assert_eq!(ino_of(&root, "/a/b/../b"), 11, ".. then back into b");
    assert_eq!(ino_of(&root, "/a/b/../b/f"), 12, ".. then descend to file");
}

// Plain deep path still resolves (the no-behaviour-change baseline).
#[test]
fn plain_path_still_resolves() {
    let root = build_root();
    assert_eq!(ino_of(&root, "/a/b/f"), 12);
}

// All four mixed together resolve identically — the consolidated splitter
// classifies Root / empty / `.` / `..` / Normal in one place.
#[test]
fn mixed_segments_match_canonical() {
    let root = build_root();
    assert_eq!(ino_of(&root, "//a/./b//../b/f"), ino_of(&root, "/a/b/f"));
}
