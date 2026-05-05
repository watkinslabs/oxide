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

#[test]
fn fdtable_live_fds_empty() {
    let t = FdTable::new();
    assert!(t.live_fds().is_empty());
}

#[test]
fn fdtable_live_fds_ascending_skips_holes() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    t.close(b).unwrap();
    let live = t.live_fds();
    assert_eq!(live, alloc::vec![a, c]);
}

#[test]
fn fdtable_live_fds_after_dup_then_close_range_semantics() {
    // Mirrors the close_range loop in kernel/src/syscall_glue_fs.rs.
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap(); // 0
    let b = t.alloc(mk_file()).unwrap(); // 1
    let c = t.alloc(mk_file()).unwrap(); // 2
    let d = t.alloc(mk_file()).unwrap(); // 3
    let (first, last) = (b, d);
    for fd in t.live_fds() {
        if fd >= first && fd <= last { t.close(fd).unwrap(); }
    }
    assert_eq!(t.live_fds(), alloc::vec![a]);
    let _ = (b, c, d); // touched
}

#[test]
fn fdtable_live_fds_cloexec_only_range() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    let (first, last) = (a, b);
    for fd in t.live_fds() {
        if fd >= first && fd <= last { t.set_cloexec(fd, true).unwrap(); }
    }
    assert!(t.cloexec(a).unwrap());
    assert!(t.cloexec(b).unwrap());
    assert!(!t.cloexec(c).unwrap());
    // No fd was closed.
    assert_eq!(t.live_fds(), alloc::vec![a, b, c]);
}

// ---------------------------------------------------------------------------
// dirent64 packing — `19§4` Linux ABI byte layout
// ---------------------------------------------------------------------------

#[test]
fn dirent64_reclen_pads_to_8_bytes() {
    // header(19) + name + NUL, padded to multiple of 8.
    assert_eq!(crate::dirent::dirent64_reclen(0),  24);  // 19+1=20 → 24
    assert_eq!(crate::dirent::dirent64_reclen(1),  24);  // 19+2=21 → 24
    assert_eq!(crate::dirent::dirent64_reclen(4),  24);  // 19+5=24 → 24
    assert_eq!(crate::dirent::dirent64_reclen(5),  32);  // 19+6=25 → 32
    assert_eq!(crate::dirent::dirent64_reclen(13), 40);  // 19+14=33 → 40
}

#[test]
fn dirent64_pack_layout_matches_linux_abi() {
    let mut buf = [0xAAu8; 64];
    let n = crate::dirent::dirent64_pack(&mut buf, 0x1122_3344_5566_7788, 0x42, 8, b"foo")
        .unwrap();
    assert_eq!(n, 24);
    // d_ino LE
    assert_eq!(&buf[0..8], &0x1122_3344_5566_7788u64.to_le_bytes());
    // d_off LE
    assert_eq!(&buf[8..16], &0x42u64.to_le_bytes());
    // d_reclen LE u16
    assert_eq!(&buf[16..18], &24u16.to_le_bytes());
    // d_type
    assert_eq!(buf[18], 8);
    // name + NUL pad
    assert_eq!(&buf[19..22], b"foo");
    assert_eq!(&buf[22..24], &[0, 0]);
}

#[test]
fn dirent64_pack_returns_none_when_buf_too_small() {
    let mut buf = [0u8; 8];
    assert_eq!(crate::dirent::dirent64_pack(&mut buf, 0, 0, 8, b"x"), None);
}

#[test]
fn dirent64_pack_many_stops_at_first_overflow() {
    let mut buf = [0u8; 48]; // exactly 2 records with name "x" (24 each)
    let names = [b"a".as_slice(), b"b", b"c"];
    let n = crate::dirent::dirent64_pack_many(
        &mut buf,
        names.iter().enumerate(),
        |(i, name)| (i as u64, (i + 1) as u64, 8, name.to_vec()),
    );
    assert_eq!(n, 48);
    // First record d_off (cookie) = 1, second = 2.
    assert_eq!(&buf[8..16], &1u64.to_le_bytes());
    assert_eq!(&buf[24+8..24+16], &2u64.to_le_bytes());
}

// Touch the warning-silencer.
#[allow(dead_code)]
fn _unused_silence() {
    let _: AtomicU64 = AtomicU64::new(0);
    let _ = Ordering::Relaxed;
}

#[test]
fn resolve_against_cwd_passthrough_absolute() {
    use crate::path::resolve_against_cwd;
    assert_eq!(resolve_against_cwd("/tmp", "/etc/passwd").as_deref(), Some("/etc/passwd"));
    assert_eq!(resolve_against_cwd("/foo", "/").as_deref(), Some("/"));
}

#[test]
fn resolve_against_cwd_joins_relative() {
    use crate::path::resolve_against_cwd;
    assert_eq!(resolve_against_cwd("/tmp", "x").as_deref(),     Some("/tmp/x"));
    assert_eq!(resolve_against_cwd("/tmp", "./x").as_deref(),   Some("/tmp/x"));
    assert_eq!(resolve_against_cwd("/tmp/", "x").as_deref(),    Some("/tmp/x"));
    assert_eq!(resolve_against_cwd("/", "etc/passwd").as_deref(), Some("/etc/passwd"));
}

#[test]
fn resolve_against_cwd_handles_dotdot() {
    use crate::path::resolve_against_cwd;
    assert_eq!(resolve_against_cwd("/tmp/sub", "../x").as_deref(), Some("/tmp/x"));
    assert_eq!(resolve_against_cwd("/tmp", "..").as_deref(),       Some("/"));
    assert_eq!(resolve_against_cwd("/", ".."), None, "above-root must reject");
}

#[test]
fn inode_default_truncate_returns_erofs() {
    // MemFile doesn't override truncate → uses the trait default.
    let i = MemFile::new(1);
    assert_eq!(i.truncate(0), Err(VfsError::Erofs));
}
