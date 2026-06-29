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

// Per-inode backing state (the old `MemFile` fields), stored in `i_private`.
struct MemFileData {
    body: RwLock<Vec<u8>, InodeClass>,
}

// Data-path ops for the in-memory file. Reads/writes the byte buffer off
// `i_private` and keeps `i_size` in sync (the concrete inode owns its size).
struct MemFileOps;
impl FileOps for MemFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<MemFileData>().unwrap();
        let body = d.body.read();
        if off >= body.len() as u64 { return Ok(0); }
        let start = off as usize;
        let avail = body.len() - start;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&body[start..start + n]);
        Ok(n)
    }
    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<MemFileData>().unwrap();
        let mut body = d.body.write();
        let end = off as usize + buf.len();
        if body.len() < end { body.resize(end, 0); }
        body[off as usize..end].copy_from_slice(buf);
        inode.set_size(body.len() as u64);
        Ok(buf.len())
    }
}

// Namespace facade over the old `MemFile` ZST: `MemFile::new(ino)` now stamps
// the concrete `Inode` (Regular, MemFileOps data path, default i_op).
struct MemFile;
impl MemFile {
    fn new(ino: u64) -> InodeRef {
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(MemFileOps))
            .private(Arc::new(MemFileData { body: RwLock::new(Vec::new()) }))
            .build()
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
fn lexical_normalize_clamps_dotdot_at_absolute_root() {
    assert_eq!(lexical_normalize("/..").as_deref(), Some("/"));
    assert_eq!(lexical_normalize("/a/../..").as_deref(), Some("/"));
    assert_eq!(lexical_normalize("/../../a").as_deref(), Some("/a"));
}

// ---------------------------------------------------------------------------
// fd-link / dup-fd parsing (T8 — /dev/std*, /dev/fd/N, /proc/<pid>/fd/N).
// The Linux magic-fd-link open/readlink/reopen contract: these paths
// resolve by duplicating an existing open file description, NOT by a
// normal path walk. Locks the parsing so the console/serial fd plumbing
// can't silently regress (the `/dev/stdout`→fd 1 reopen path).
// ---------------------------------------------------------------------------

#[test]
fn dup_fd_target_std_streams() {
    use crate::path::dup_fd_target;
    assert_eq!(dup_fd_target("/dev/stdin"),  Some((None, 0)));
    assert_eq!(dup_fd_target("/dev/stdout"), Some((None, 1)));
    assert_eq!(dup_fd_target("/dev/stderr"), Some((None, 2)));
}

#[test]
fn dup_fd_target_dev_fd_n() {
    use crate::path::dup_fd_target;
    assert_eq!(dup_fd_target("/dev/fd/0"),  Some((None, 0)));
    assert_eq!(dup_fd_target("/dev/fd/1"),  Some((None, 1)));
    assert_eq!(dup_fd_target("/dev/fd/42"), Some((None, 42)));
    // Not a valid fd number → not an fd-link (resolve normally).
    assert_eq!(dup_fd_target("/dev/fd/abc"), None);
}

#[test]
fn dup_fd_target_proc_self_and_pid_fd() {
    use crate::path::{dup_fd_target, parse_proc_fd};
    assert_eq!(dup_fd_target("/proc/self/fd/0"), Some((None, 0)));
    assert_eq!(dup_fd_target("/proc/self/fd/2"), Some((None, 2)));
    assert_eq!(dup_fd_target("/proc/1/fd/1"),    Some((Some(1), 1)));
    assert_eq!(parse_proc_fd("/proc/123/fd/7"),  Some((Some(123), 7)));
    // The /proc/self/fd dir itself (no <n>) is not an fd-link target.
    assert_eq!(parse_proc_fd("/proc/self/fd"), None);
}

#[test]
fn dup_fd_target_execve_magic_fd_forms() {
    // execve("/proc/self/fd/N") and execveat(fd,"",AT_EMPTY_PATH) (the
    // latter synthesises "/proc/self/fd/<dirfd>") both route through
    // dup_fd_target so the exec loader reads the OPEN file description's
    // backing inode — the only way a sealed memfd (whose d_path can't be
    // re-resolved) is exec-able, matching Linux do_execveat_common.
    use crate::path::dup_fd_target;
    // The exact strings execve / execveat hand the loader.
    assert_eq!(dup_fd_target("/proc/self/fd/3"),  Some((None, 3)));
    assert_eq!(dup_fd_target("/proc/self/fd/17"), Some((None, 17)));
    assert_eq!(dup_fd_target("/dev/fd/3"),        Some((None, 3)));
    // Per-pid form (/proc/<pid>/fd/<n>) is exec-able too.
    assert_eq!(dup_fd_target("/proc/42/fd/3"),    Some((Some(42), 3)));
}

#[test]
fn dup_fd_target_rejects_non_fd_links() {
    use crate::path::dup_fd_target;
    // Real device + regular paths must resolve via the normal walk.
    assert_eq!(dup_fd_target("/dev/console"), None);
    assert_eq!(dup_fd_target("/dev/tty"),     None);
    assert_eq!(dup_fd_target("/etc/passwd"),  None);
    assert_eq!(dup_fd_target("/proc/self/status"), None);
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
// B6 — f_path / f_mode / f_cred / private_data + bitmap fd flags
// ---------------------------------------------------------------------------

#[test]
fn file_new_at_carries_mnt_id_in_f_path() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new_at(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR, 42, Cred::root());
    assert_eq!(f.mnt_id(), 42);
    let (mnt, dentry) = f.f_path();
    assert_eq!(mnt, 42);
    assert!(Arc::ptr_eq(dentry, &d));
    // The plain `new` ctor is the anonymous-inode form: no vfsmount.
    let anon = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);
    assert_eq!(anon.mnt_id(), 0);
    assert!(anon.vfsmount().is_none());
}

#[test]
fn file_f_inode_matches_dentry_inode() {
    let i: InodeRef = MemFile::new(7);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new_at(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDONLY, 1, Cred::root());
    assert_eq!(f.f_inode().ino(), 7);
    assert_eq!(f.f_inode().ino(), f.dentry().inode().unwrap().ino());
}

#[test]
fn file_f_mode_derivation() {
    use crate::file::Fmode;
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    // MemFile is a regular (seekable) file, so every open also carries the
    // FMODE_LSEEK|PREAD|PWRITE capability bits (`do_dentry_open`). Mask them
    // out to assert the access-mode derivation in isolation, then assert the
    // seekability bits are present.
    let seek = Fmode::LSEEK | Fmode::PREAD | Fmode::PWRITE;
    let ro = File::new_at(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDONLY, 0, Cred::root());
    assert_eq!(ro.f_mode() - seek, Fmode::READ);
    assert!(ro.f_mode().contains(seek), "regular file is seekable");
    let wo = File::new_at(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_WRONLY, 0, Cred::root());
    assert_eq!(wo.f_mode() - seek, Fmode::WRITE);
    let rw = File::new_at(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR, 0, Cred::root());
    assert_eq!(rw.f_mode() - seek, Fmode::READ | Fmode::WRITE);
}

#[test]
fn file_f_cred_snapshot() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let cred = Cred { uid: 1000, gid: 1001, cap_dac_override: false, cap_dac_read_search: true,
        cap_fowner: false, cap_chown: false, cap_fsetid: false, ngroups: 0, groups: [0u32; CRED_NGROUPS] };
    let f = File::new_at(i, d, OpenFlags::O_RDONLY, 0, cred);
    assert_eq!(f.f_cred().uid, 1000);
    assert_eq!(f.f_cred().gid, 1001);
    assert!(!f.f_cred().cap_dac_override);
    assert!(f.f_cred().cap_dac_read_search);
}

#[test]
fn file_private_data_round_trip() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(i, d, OpenFlags::O_RDONLY);
    assert_eq!(f.private_data(), 0);
    f.set_private_data(0xDEAD_BEEF);
    assert_eq!(f.private_data(), 0xDEAD_BEEF);
}

#[test]
fn fdtable_dup_shares_file_and_mnt() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new_at(i, d, OpenFlags::O_RDWR, 7, Cred::root());
    let t = FdTable::new();
    let a = t.alloc(f).unwrap();
    let b = t.dup(a).unwrap();
    assert_ne!(a, b);
    assert!(Arc::ptr_eq(&t.get(a).unwrap(), &t.get(b).unwrap()));
    // The mount rides along with the shared open file description.
    assert_eq!(t.get(b).unwrap().mnt_id(), 7);
}

#[test]
fn fdtable_dup_has_independent_cloexec() {
    // dup* share the File (Arc) but the FD_CLOEXEC flag is per-fd.
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.dup(a).unwrap();
    t.set_cloexec(b, true).unwrap();
    assert!(!t.cloexec(a).unwrap(), "original fd keeps its own (clear) flag");
    assert!(t.cloexec(b).unwrap(),  "dup'd fd has its own (set) flag");
}

#[test]
fn fdtable_f_setfd_sets_close_on_exec() {
    // Models fcntl(F_SETFD, FD_CLOEXEC) → set_cloexec, then execve drop.
    let t = FdTable::new();
    let keep = t.alloc(mk_file()).unwrap();
    let drop = t.alloc(mk_file()).unwrap();
    t.set_cloexec(drop, true).unwrap();
    assert!(t.cloexec(drop).unwrap());
    t.close_on_exec();
    assert!(t.get(keep).is_ok(), "non-cloexec fd survives execve");
    assert_eq!(t.get(drop).err(), Some(VfsError::Ebadf), "cloexec fd dropped");
    // The flag was cleared on the surviving fd too.
    assert!(!t.cloexec(keep).unwrap());
}

#[test]
fn fdtable_close_range_closes_span() {
    // Models close_range(first,last): close the inclusive [first,last] span.
    let t = FdTable::new();
    let f0 = t.alloc(mk_file()).unwrap(); // 0
    let f1 = t.alloc(mk_file()).unwrap(); // 1
    let f2 = t.alloc(mk_file()).unwrap(); // 2
    let f3 = t.alloc(mk_file()).unwrap(); // 3
    let f4 = t.alloc(mk_file()).unwrap(); // 4
    let (first, last) = (f1, f3);
    for fd in t.live_fds() {
        if fd >= first && fd <= last { t.close(fd).unwrap(); }
    }
    assert!(t.get(f0).is_ok());
    assert_eq!(t.get(f1).err(), Some(VfsError::Ebadf));
    assert_eq!(t.get(f2).err(), Some(VfsError::Ebadf));
    assert_eq!(t.get(f3).err(), Some(VfsError::Ebadf));
    assert!(t.get(f4).is_ok());
    assert_eq!(t.live_fds(), alloc::vec![f0, f4]);
}

#[test]
fn install_open_o_cloexec_sets_fd_flag_not_file_flag() {
    let t = FdTable::new();
    let i: InodeRef = MemFile::new(2);
    let fd = crate::file::install_open(
        &t,
        Arc::clone(&i),
        "/tmp/created",
        OpenFlags::O_RDWR | OpenFlags::O_CLOEXEC,
        0,
        crate::namei::Cred::root(),
    ).unwrap();
    assert!(t.cloexec(fd).unwrap());
    assert!(!t.get(fd).unwrap().flags().contains(OpenFlags::O_CLOEXEC));
    assert!(t.get(fd).unwrap().flags().contains(OpenFlags::O_RDWR));
}

#[test]
fn fdtable_bitmap_alloc_min_skips_full_words() {
    // Allocate past the first 64-fd word, free one in word 0, and a
    // min-bounded alloc must respect `min` (F_DUPFD semantics) — exercising
    // the word-scan free-fd search across word boundaries.
    let t = FdTable::new();
    let mut fds = alloc::vec::Vec::new();
    for _ in 0..70 { fds.push(t.alloc(mk_file()).unwrap()); }
    assert_eq!(fds.last().copied(), Some(69));
    t.close(3).unwrap();
    // Lowest free is now 3.
    assert_eq!(t.alloc(mk_file()).unwrap(), 3);
    // A min-bounded dup lands at >= 70 (all of 0..=69 occupied).
    let dd = t.dup_min(0, 70).unwrap();
    assert_eq!(dd, 70);
}

#[test]
fn fdtable_flush_fires_on_close() {
    use core::sync::atomic::{AtomicUsize, Ordering as O};
    static FLUSHED: AtomicUsize = AtomicUsize::new(0);
    struct FlushOps;
    impl FileOps for FlushOps {
        fn read(&self, _i: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
        fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
        fn on_flush(&self, _i: &Inode) { FLUSHED.fetch_add(1, O::Relaxed); }
    }
    FLUSHED.store(0, O::Relaxed);
    let i: InodeRef = InodeBuilder::new(9, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(FlushOps)).build();
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(i, d, OpenFlags::O_RDWR);
    let t = FdTable::new();
    let a = t.alloc(f).unwrap();
    let b = t.dup(a).unwrap();
    // Each close(2) flushes (per-fd), even though the Arc is shared.
    t.close(a).unwrap();
    t.close(b).unwrap();
    assert_eq!(FLUSHED.load(O::Relaxed), 2);
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

// ---------------------------------------------------------------------------
// legacy linux_dirent packing (getdents(2), NR 78) — distinct from dirent64
// ---------------------------------------------------------------------------

#[test]
fn dirent_legacy_reclen_pads_to_8_bytes() {
    // header(18) + name + NUL + d_type byte, padded to multiple of 8.
    assert_eq!(crate::dirent::dirent_reclen(0),  24); // 18+0+2=20 → 24
    assert_eq!(crate::dirent::dirent_reclen(3),  24); // 18+3+2=23 → 24
    assert_eq!(crate::dirent::dirent_reclen(4),  24); // 18+4+2=24 → 24
    assert_eq!(crate::dirent::dirent_reclen(5),  32); // 18+5+2=25 → 32
    assert_eq!(crate::dirent::dirent_reclen(13), 40); // 18+13+2=33 → 40
}

#[test]
fn dirent_legacy_pack_layout_matches_linux_abi() {
    let mut buf = [0xAAu8; 64];
    let n = crate::dirent::dirent_pack(&mut buf, 0x1122_3344_5566_7788, 0x42, 8, b"foo")
        .unwrap();
    assert_eq!(n, 24);
    assert_eq!(&buf[0..8],  &0x1122_3344_5566_7788u64.to_le_bytes()); // d_ino
    assert_eq!(&buf[8..16], &0x42u64.to_le_bytes());                  // d_off
    assert_eq!(&buf[16..18], &24u16.to_le_bytes());                   // d_reclen
    assert_eq!(&buf[18..21], b"foo");                                 // d_name @18
    assert_eq!(buf[21], 0);                                           // NUL term
    // zero padding between NUL and the trailing d_type byte
    assert_eq!(&buf[22..23], &[0]);
    // d_type lives in the LAST byte of the record (legacy ABI wart).
    assert_eq!(buf[n - 1], 8);
}

#[test]
fn dirent_legacy_pack_returns_none_when_buf_too_small() {
    // The handler relies on this None → first-record-overflow → EINVAL.
    let mut buf = [0u8; 8];
    assert_eq!(crate::dirent::dirent_pack(&mut buf, 0, 0, 8, b"x"), None);
}

// ---------------------------------------------------------------------------
// byte-wise (non-UTF-8) path handling — Linux paths are opaque byte strings
// ---------------------------------------------------------------------------

#[test]
fn path_from_bytes_keeps_valid_utf8_verbatim() {
    assert_eq!(crate::path::path_from_bytes(b"/etc/passwd"), "/etc/passwd");
    // multi-byte UTF-8 stays intact and round-trips.
    let s = crate::path::path_from_bytes("/café".as_bytes());
    assert_eq!(crate::path::path_into_bytes(&s), "/café".as_bytes());
}

#[test]
fn path_from_bytes_roundtrips_non_utf8() {
    let raw = b"file\xff\xfename";
    let s = crate::path::path_from_bytes(raw);
    assert_eq!(crate::path::path_into_bytes(&s), raw);
}

// ---------------------------------------------------------------------------
// RENAME_EXCHANGE / RENAME_WHITEOUT + non-UTF-8 resolution against a mock FS
// ---------------------------------------------------------------------------

use alloc::collections::BTreeMap;

/// Single-level directory inode storing byte-exact entry names. Lookups
/// decode the escaped `&str` back to its on-disk bytes, exercising the
/// byte-wise resolution contract.
struct TestDir {
    ino:  u64,
    ents: RwLock<BTreeMap<Vec<u8>, (u64, FileType, u32)>, InodeClass>,
}

impl TestDir {
    fn new() -> Arc<Self> {
        Arc::new(Self { ino: 1, ents: RwLock::new(BTreeMap::new()) })
    }
    fn insert(&self, name: &[u8], ino: u64, ft: FileType, rdev: u32) {
        self.ents.write().insert(name.to_vec(), (ino, ft, rdev));
    }
    fn get(&self, name: &[u8]) -> Option<(u64, FileType, u32)> {
        self.ents.read().get(name).copied()
    }
    // Build the concrete directory inode backed by this `TestDir` (stored as
    // `i_private`; `TestDirOps` reads it back via `inode.private::<TestDir>()`).
    fn inode(self: &Arc<Self>) -> InodeRef {
        InodeBuilder::new(self.ino, mk_mode(FileType::Directory, 0o755),
            Arc::new(TestDirOps), default_file_ops())
            .private(self.clone())
            .build()
    }
}

struct TestDirOps;
impl InodeOps for TestDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<TestDir>().unwrap();
        let key = crate::path::path_into_bytes(name);
        match d.ents.read().get(&key) {
            Some(&(ino, _, _)) => { let r: InodeRef = MemFile::new(ino); Ok(r) }
            None => Err(VfsError::Enoent),
        }
    }
    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32) -> KResult<()> {
        let d = inode.private::<TestDir>().unwrap();
        let key = crate::path::path_into_bytes(name);
        let ft = match mode & 0xF000 {
            0x2000 => FileType::CharDev,
            0x6000 => FileType::BlockDev,
            0x1000 => FileType::Fifo,
            0xC000 => FileType::Socket,
            _      => FileType::Regular,
        };
        d.ents.write().insert(key, (0, ft, rdev));
        Ok(())
    }
}

struct TestFs { dir: Arc<TestDir> }

impl crate::fs::FileSystem for TestFs {
    fn name(&self) -> &str { "testfs" }
    fn root(&self) -> Option<InodeRef> { Some(self.dir.inode()) }
    fn rename(&self, from: &str, to: &str) -> KResult<()> {
        let fk = crate::path::path_into_bytes(from);
        let tk = crate::path::path_into_bytes(to);
        let mut e = self.dir.ents.write();
        let v = e.remove(&fk).ok_or(VfsError::Enoent)?;
        e.insert(tk, v);
        Ok(())
    }
}

#[test]
fn rename_exchange_swaps_two_files() {
    use crate::fs::FileSystem;
    let fs = TestFs { dir: TestDir::new() };
    fs.dir.insert(b"a", 11, FileType::Regular, 0);
    fs.dir.insert(b"b", 22, FileType::Regular, 0);
    fs.exchange("a", "b").unwrap();
    assert_eq!(fs.dir.get(b"a").unwrap().0, 22);
    assert_eq!(fs.dir.get(b"b").unwrap().0, 11);
    assert_eq!(fs.dir.ents.read().len(), 2); // temp name cleaned up
}

#[test]
fn rename_exchange_missing_side_is_enoent() {
    use crate::fs::FileSystem;
    let fs = TestFs { dir: TestDir::new() };
    fs.dir.insert(b"a", 11, FileType::Regular, 0);
    assert_eq!(fs.exchange("a", "nope"), Err(VfsError::Enoent));
}

#[test]
fn rename_whiteout_plants_chardev_at_source() {
    use crate::fs::FileSystem;
    let fs = TestFs { dir: TestDir::new() };
    fs.dir.insert(b"src", 11, FileType::Regular, 0);
    fs.whiteout("src", "dst").unwrap();
    assert_eq!(fs.dir.get(b"dst").unwrap().0, 11); // file moved to dest
    let (_, ft, rdev) = fs.dir.get(b"src").unwrap();
    assert_eq!(ft, FileType::CharDev);             // whiteout = char dev
    assert_eq!(rdev, 0);                           //          rdev 0/0
}

#[test]
fn non_utf8_filename_resolves_and_stats() {
    use crate::fs::FileSystem;
    let fs = TestFs { dir: TestDir::new() };
    let name = b"caf\xe9"; // trailing 0xE9 — invalid UTF-8
    fs.dir.insert(name, 77, FileType::Regular, 0);
    // userspace handed these raw bytes; decode as read_user_path does.
    let path = crate::path::path_from_bytes(name);
    let ino = fs.lookup_path(&path).expect("non-utf8 name resolves");
    assert_eq!(ino.ino(), 77); // stat reads the resolved inode number
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
    assert_eq!(resolve_against_cwd("/", "..").as_deref(), Some("/"));
}

#[test]
fn inode_default_truncate_returns_erofs() {
    // MemFile doesn't override truncate → uses the trait default.
    let i = MemFile::new(1);
    assert_eq!(i.truncate(0), Err(VfsError::Erofs));
}

#[test]
fn trim_hostname_strips_trailing_newline_and_nul() {
    use crate::path::trim_hostname;
    assert_eq!(trim_hostname(b"host\n",  64), b"host");
    assert_eq!(trim_hostname(b"host\0",  64), b"host");
    assert_eq!(trim_hostname(b"host\n\0", 64), b"host");
    assert_eq!(trim_hostname(b"plain",   64), b"plain");
}

#[test]
fn trim_hostname_clamps_to_max() {
    use crate::path::trim_hostname;
    let long = b"abcdefghij";
    assert_eq!(trim_hostname(long, 4), b"abcd");
}

#[test]
fn trim_hostname_empty_stays_empty() {
    use crate::path::trim_hostname;
    assert_eq!(trim_hostname(b"",       64), b"");
    assert_eq!(trim_hostname(b"\n",     64), b"");
    assert_eq!(trim_hostname(b"\n\n\0", 64), b"");
}

// ---- F197: Dentry::absolute_path -----------------------------------

#[test]
fn dentry_absolute_path_root_is_slash() {
    let i: InodeRef = MemFile::new(1);
    let root = Dentry::new_root(i);
    assert_eq!(root.absolute_path(), b"/");
}

#[test]
fn dentry_absolute_path_single_component() {
    let i: InodeRef = MemFile::new(1);
    let root = Dentry::new_root(Arc::clone(&i));
    let bin  = Dentry::new(Some(root), String::from("bin"), Arc::clone(&i));
    assert_eq!(bin.absolute_path(), b"/bin");
}

#[test]
fn dentry_absolute_path_nested_components() {
    let i: InodeRef = MemFile::new(1);
    let root = Dentry::new_root(Arc::clone(&i));
    let sbin = Dentry::new(Some(root),           String::from("sbin"), Arc::clone(&i));
    let exe  = Dentry::new(Some(Arc::clone(&sbin)), String::from("init"), Arc::clone(&i));
    assert_eq!(exe.absolute_path(), b"/sbin/init");
}

#[test]
fn dentry_absolute_path_open_dentry_shape() {
    // WP2: an opened file's dentry is PARENTED (the basename hangs off the
    // resolved parent dentry — `file::open_dentry`), so the pathname is
    // reconstructed by the parent walk. There is NO whole-path-in-one-name
    // special case: a parentless dentry whose name contains slashes would be
    // an invalid shape and is never built by the open path.
    let i: InodeRef = MemFile::new(1);
    let root = Dentry::new_root(Arc::clone(&i));
    let dev  = Dentry::new(Some(root),            String::from("dev"), Arc::clone(&i));
    let pts  = Dentry::new(Some(Arc::clone(&dev)), String::from("pts"), Arc::clone(&i));
    let three = Dentry::new_child(&pts, "3", Some(Arc::clone(&i)));
    assert_eq!(three.absolute_path(), b"/dev/pts/3");
}

#[test]
fn dentry_absolute_path_deep_chain() {
    let i: InodeRef = MemFile::new(1);
    let root = Dentry::new_root(Arc::clone(&i));
    let a    = Dentry::new(Some(root),            String::from("usr"),   Arc::clone(&i));
    let b    = Dentry::new(Some(Arc::clone(&a)),  String::from("share"), Arc::clone(&i));
    let c    = Dentry::new(Some(Arc::clone(&b)),  String::from("zoneinfo"), Arc::clone(&i));
    let leaf = Dentry::new(Some(Arc::clone(&c)),  String::from("UTC"),   Arc::clone(&i));
    assert_eq!(leaf.absolute_path(), b"/usr/share/zoneinfo/UTC");
}
