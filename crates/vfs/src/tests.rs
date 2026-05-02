// Hosted tests for the VFS foundation. Per `16§9` test contract: path
// resolution + cache shape + FD lifecycle. Cache impl + symlink +
// mount + RESOLVE_BENEATH ride in follow-up PRs.

extern crate alloc;
use super::*;
use crate::dentry::Dentry;
use crate::fdtable::FdTable;
use crate::file::{File, SeekFrom};
use crate::inode::{Inode, InodeRef};
use crate::path::{components, is_absolute, lexical_normalize, Component};
use crate::types::{FileType, OpenFlags, VfsError};

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{RwLock, Inode as InodeClass};

// ---------------------------------------------------------------------------
// In-memory test inode — minimal Regular + Directory inodes for the FS surface
// ---------------------------------------------------------------------------

struct MemFile {
    ino:  u64,
    body: RwLock<Vec<u8>, InodeClass>,
}

impl MemFile {
    fn new(ino: u64) -> Arc<Self> {
        Arc::new(Self { ino, body: RwLock::new(Vec::new()) })
    }
}

impl Inode for MemFile {
    fn ino(&self) -> u64 { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.body.read().len() as u64 }

    fn lookup(&self, _name: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = self.body.read();
        if off >= body.len() as u64 { return Ok(0); }
        let start = off as usize;
        let avail = body.len() - start;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&body[start..start + n]);
        Ok(n)
    }
    fn write(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        let mut body = self.body.write();
        let end = off as usize + buf.len();
        if body.len() < end { body.resize(end, 0); }
        body[off as usize..end].copy_from_slice(buf);
        Ok(buf.len())
    }
}

// ---------------------------------------------------------------------------
// Path component splitting
// ---------------------------------------------------------------------------

#[test]
fn components_root_only() {
    assert_eq!(components("/"), [Component::Root]);
}

#[test]
fn components_simple_absolute() {
    assert_eq!(
        components("/a/b/c"),
        [Component::Root, Component::Normal("a"), Component::Normal("b"), Component::Normal("c")]
    );
}

#[test]
fn components_collapses_repeated_slashes() {
    assert_eq!(
        components("/a//b///c/"),
        [Component::Root, Component::Normal("a"), Component::Normal("b"), Component::Normal("c")]
    );
}

#[test]
fn components_skips_dots_and_keeps_dotdots() {
    assert_eq!(
        components("./a/./b/../c"),
        [Component::Normal("a"), Component::Normal("b"), Component::ParentDir, Component::Normal("c")]
    );
}

#[test]
fn components_relative_path() {
    assert_eq!(
        components("a/b"),
        [Component::Normal("a"), Component::Normal("b")]
    );
}

#[test]
fn is_absolute_distinguishes() {
    assert!(is_absolute("/"));
    assert!(is_absolute("/foo"));
    assert!(!is_absolute("foo"));
    assert!(!is_absolute(""));
}

#[test]
fn lexical_normalize_resolves_dotdot() {
    assert_eq!(lexical_normalize("/a/b/../c").as_deref(), Some("/a/c"));
    assert_eq!(lexical_normalize("/a/./b").as_deref(),    Some("/a/b"));
    assert_eq!(lexical_normalize("a/b/../c").as_deref(),  Some("a/c"));
    assert_eq!(lexical_normalize("/").as_deref(),          Some("/"));
    assert_eq!(lexical_normalize("a/..").as_deref(),       Some("."));
}

#[test]
fn lexical_normalize_rejects_dotdot_above_absolute_root() {
    assert!(lexical_normalize("/..").is_none());
    assert!(lexical_normalize("/a/../..").is_none());
}

// ---------------------------------------------------------------------------
// Dentry
// ---------------------------------------------------------------------------

#[test]
fn dentry_roundtrip_positive_negative() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    assert_eq!(d.name(), "");
    assert!(d.parent().is_none());
    assert!(!d.is_negative());
    assert!(d.inode().is_some());

    let neg = Dentry::new_negative(Some(Arc::clone(&d)), String::from("missing"));
    assert!(neg.is_negative());
    assert_eq!(neg.name(), "missing");
    assert!(neg.inode().is_none());

    // Promote the negative dentry on a future create.
    neg.set_inode(Some(MemFile::new(2)));
    assert!(!neg.is_negative());
}

// ---------------------------------------------------------------------------
// File
// ---------------------------------------------------------------------------

#[test]
fn file_read_write_roundtrip() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);

    let n = f.write(b"hello").unwrap();
    assert_eq!(n, 5);
    assert_eq!(f.pos(), 5);

    f.set_pos(0);
    let mut buf = [0u8; 16];
    let n = f.read(&mut buf).unwrap();
    assert_eq!(n, 5);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(f.pos(), 5);
}

#[test]
fn file_read_on_writeonly_is_ebadf() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_WRONLY);
    let mut buf = [0u8; 4];
    assert_eq!(f.read(&mut buf), Err(VfsError::Ebadf));
}

#[test]
fn file_write_on_readonly_is_ebadf() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDONLY);
    assert_eq!(f.write(b"x"), Err(VfsError::Ebadf));
}

#[test]
fn file_append_uses_inode_size() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    // First, write 5 bytes via a normal RDWR handle.
    let writer = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);
    writer.write(b"hello").unwrap();
    // Now an O_APPEND handle: even with pos=0 the write must land at end.
    let appender = File::new(
        Arc::clone(&i),
        Arc::clone(&d),
        OpenFlags::O_WRONLY | OpenFlags::O_APPEND,
    );
    appender.set_pos(0);
    let n = appender.write(b"WORLD").unwrap();
    assert_eq!(n, 5);
    // Read the whole thing back.
    let mut buf = [0u8; 16];
    let r = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDONLY);
    let n = r.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"helloWORLD");
}

#[test]
fn file_seek_set_cur_end() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);
    f.write(b"abcdefgh").unwrap();
    assert_eq!(f.seek(SeekFrom::Start, 2).unwrap(), 2);
    assert_eq!(f.seek(SeekFrom::Current, 3).unwrap(), 5);
    assert_eq!(f.seek(SeekFrom::End, -1).unwrap(),    7);
    assert_eq!(f.seek(SeekFrom::Start, 100).unwrap(), 100); // past end OK
}

// ---------------------------------------------------------------------------
// FdTable
// ---------------------------------------------------------------------------

fn mk_file() -> Arc<File> {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    File::new(i, d, OpenFlags::O_RDWR)
}

#[test]
fn fdtable_alloc_lowest_first() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    assert_eq!((a, b, c), (0, 1, 2));
}

#[test]
fn fdtable_close_then_realloc_fills_hole() {
    let t = FdTable::new();
    let _ = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let _ = t.alloc(mk_file()).unwrap();
    t.close(b).unwrap();
    // The freed slot must be reused.
    let d = t.alloc(mk_file()).unwrap();
    assert_eq!(d, b);
}

#[test]
fn fdtable_close_invalid_fd() {
    let t = FdTable::new();
    assert_eq!(t.close(0),  Err::<(), _>(VfsError::Ebadf));
    assert_eq!(t.close(-1), Err::<(), _>(VfsError::Ebadf));
}

#[test]
fn fdtable_dup_yields_new_fd_same_file() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.dup(a).unwrap();
    assert_ne!(a, b);
    assert!(Arc::ptr_eq(&t.get(a).unwrap(), &t.get(b).unwrap()));
}

#[test]
fn fdtable_dup2_replaces_existing() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    // Replace b with a copy of a.
    let r = t.dup2(a, b).unwrap();
    assert_eq!(r, b);
    assert!(Arc::ptr_eq(&t.get(a).unwrap(), &t.get(b).unwrap()));
}

#[test]
fn fdtable_dup2_same_fd_is_noop() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let r = t.dup2(a, a).unwrap();
    assert_eq!(r, a);
}

#[test]
fn fdtable_cloexec_set_get() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    assert_eq!(t.cloexec(a).unwrap(), false);
    t.set_cloexec(a, true).unwrap();
    assert_eq!(t.cloexec(a).unwrap(), true);
    // Bogus fd ⇒ Ebadf.
    assert_eq!(t.set_cloexec(99, true), Err(VfsError::Ebadf));
}

#[test]
fn fdtable_close_on_exec_drops_marked() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    t.set_cloexec(b, true).unwrap();
    t.close_on_exec();
    assert!(t.get(a).is_ok());
    assert_eq!(t.get(b).err(), Some(VfsError::Ebadf));
    assert!(t.get(c).is_ok());
}

#[test]
fn fdtable_concurrent_alloc_close() {
    use std::sync::Arc as StdArc;
    use std::thread;
    let t: StdArc<FdTable> = StdArc::new(FdTable::new());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let t = StdArc::clone(&t);
        handles.push(thread::spawn(move || {
            for _ in 0..200 {
                if let Ok(fd) = t.alloc(mk_file()) {
                    let _ = t.close(fd);
                }
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    // Every alloc was paired with a close; final count must be 0.
    assert_eq!(t.count(), 0);
}

// Touch the warning-silencer.
#[allow(dead_code)]
fn _unused_silence() {
    let _: AtomicU64 = AtomicU64::new(0);
    let _ = Ordering::Relaxed;
}
