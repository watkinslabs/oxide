use super::*;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

fn mk_file() -> Arc<File> {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    File::new(i, d, OpenFlags::O_RDWR)
}

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
    let writer = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);
    writer.write(b"hello").unwrap();
    let appender = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_WRONLY | OpenFlags::O_APPEND);
    appender.set_pos(0);
    assert_eq!(appender.write(b"WORLD").unwrap(), 5);
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
    assert_eq!(f.seek(SeekFrom::Start, 100).unwrap(), 100);
}

#[test]
fn file_seek_data_hole_generic() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);
    f.write(b"abcdefgh").unwrap();
    assert_eq!(f.seek(SeekFrom::Data, 0).unwrap(), 0);
    assert_eq!(f.seek(SeekFrom::Data, 3).unwrap(), 3);
    assert_eq!(f.seek(SeekFrom::Hole, 0).unwrap(), 8);
    assert_eq!(f.seek(SeekFrom::Hole, 7).unwrap(), 8);
    assert_eq!(f.seek(SeekFrom::Data, 8), Err(VfsError::Enxio));
    assert_eq!(f.seek(SeekFrom::Hole, 8), Err(VfsError::Enxio));
    assert_eq!(f.seek(SeekFrom::Data, 100), Err(VfsError::Enxio));
    assert_eq!(f.seek(SeekFrom::Data, -1), Err(VfsError::Einval));
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
    assert_eq!(t.alloc(mk_file()).unwrap(), b);
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
    assert_eq!(t.dup2(a, b).unwrap(), b);
    assert!(Arc::ptr_eq(&t.get(a).unwrap(), &t.get(b).unwrap()));
}

#[test]
fn fdtable_dup2_same_fd_is_noop() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup2(a, a).unwrap(), a);
}

#[test]
fn fdtable_cloexec_set_get() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    assert_eq!(t.cloexec(a).unwrap(), false);
    t.set_cloexec(a, true).unwrap();
    assert_eq!(t.cloexec(a).unwrap(), true);
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
                if let Ok(fd) = t.alloc(mk_file()) { let _ = t.close(fd); }
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
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
    assert_eq!(t.live_fds(), alloc::vec![a, c]);
}

#[test]
fn fdtable_live_fds_after_dup_then_close_range_semantics() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    let d = t.alloc(mk_file()).unwrap();
    for fd in t.live_fds() {
        if fd >= b && fd <= d { t.close(fd).unwrap(); }
    }
    assert_eq!(t.live_fds(), alloc::vec![a]);
    let _ = c;
}

#[test]
fn fdtable_live_fds_cloexec_only_range() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    for fd in t.live_fds() {
        if fd >= a && fd <= b { t.set_cloexec(fd, true).unwrap(); }
    }
    assert!(t.cloexec(a).unwrap());
    assert!(t.cloexec(b).unwrap());
    assert!(!t.cloexec(c).unwrap());
    assert_eq!(t.live_fds(), alloc::vec![a, b, c]);
}

#[test]
fn file_new_at_carries_mnt_id_in_f_path() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new_at(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR, 42, crate::FileCred::root());
    assert_eq!(f.mnt_id(), 42);
    let (mnt, dentry) = f.f_path();
    assert_eq!(mnt, 42);
    assert!(Arc::ptr_eq(dentry, &d));
    let anon = File::new(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR);
    assert_eq!(anon.mnt_id(), 0);
    assert!(anon.vfsmount().is_none());
}

#[test]
fn file_f_inode_matches_dentry_inode() {
    let i: InodeRef = MemFile::new(7);
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new_at(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDONLY, 1, crate::FileCred::root());
    assert_eq!(f.f_inode().ino(), 7);
    assert_eq!(f.f_inode().ino(), f.dentry().inode().unwrap().ino());
}

#[test]
fn file_f_mode_derivation() {
    use crate::file::Fmode;
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let seek = Fmode::LSEEK | Fmode::PREAD | Fmode::PWRITE;
    let ro = File::new_at(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDONLY, 0, crate::FileCred::root());
    assert_eq!(ro.f_mode() - seek, Fmode::READ);
    assert!(ro.f_mode().contains(seek), "regular file is seekable");
    let wo = File::new_at(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_WRONLY, 0, crate::FileCred::root());
    assert_eq!(wo.f_mode() - seek, Fmode::WRITE);
    let rw = File::new_at(Arc::clone(&i), Arc::clone(&d), OpenFlags::O_RDWR, 0, crate::FileCred::root());
    assert_eq!(rw.f_mode() - seek, Fmode::READ | Fmode::WRITE);
}

#[test]
fn file_f_cred_snapshot() {
    const TEST_CAP: u32 = 5;
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    let cred = Cred { uid: 1000, gid: 1001, cap_dac_override: false, cap_dac_read_search: true,
        cap_fowner: false, cap_chown: false, cap_fsetid: false, groups: crate::GroupList::empty() };
    let user_namespace = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    let f = File::new_at(i, d, OpenFlags::O_RDONLY, 0,
        crate::FileCred::new(cred, user_namespace.clone(), 1u64 << TEST_CAP));
    assert_eq!(f.f_cred().uid, 1000);
    assert_eq!(f.f_cred().gid, 1001);
    assert!(!f.f_cred().cap_dac_override);
    assert!(f.f_cred().cap_dac_read_search);
    assert!(namespace_identity::NamespaceRef::ptr_eq(
        f.file_cred().user_namespace(), &user_namespace));
    assert!(f.file_cred().has_cap(TEST_CAP));
    assert!(!f.file_cred().has_cap(TEST_CAP + 1));
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
    let f = File::new_at(i, d, OpenFlags::O_RDWR, 7, crate::FileCred::root());
    let t = FdTable::new();
    let a = t.alloc(f).unwrap();
    let b = t.dup(a).unwrap();
    assert_ne!(a, b);
    assert!(Arc::ptr_eq(&t.get(a).unwrap(), &t.get(b).unwrap()));
    assert_eq!(t.get(b).unwrap().mnt_id(), 7);
}

#[test]
fn fdtable_dup_has_independent_cloexec() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.dup(a).unwrap();
    t.set_cloexec(b, true).unwrap();
    assert!(!t.cloexec(a).unwrap(), "original fd keeps its own (clear) flag");
    assert!(t.cloexec(b).unwrap(),  "dup'd fd has its own (set) flag");
}

#[test]
fn fdtable_f_setfd_sets_close_on_exec() {
    let t = FdTable::new();
    let keep = t.alloc(mk_file()).unwrap();
    let drop = t.alloc(mk_file()).unwrap();
    t.set_cloexec(drop, true).unwrap();
    assert!(t.cloexec(drop).unwrap());
    t.close_on_exec();
    assert!(t.get(keep).is_ok(), "non-cloexec fd survives execve");
    assert_eq!(t.get(drop).err(), Some(VfsError::Ebadf), "cloexec fd dropped");
    assert!(!t.cloexec(keep).unwrap());
}

#[test]
fn fdtable_close_range_closes_span() {
    let t = FdTable::new();
    let f0 = t.alloc(mk_file()).unwrap();
    let f1 = t.alloc(mk_file()).unwrap();
    let f2 = t.alloc(mk_file()).unwrap();
    let f3 = t.alloc(mk_file()).unwrap();
    let f4 = t.alloc(mk_file()).unwrap();
    for fd in t.live_fds() {
        if fd >= f1 && fd <= f3 { t.close(fd).unwrap(); }
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
    let d = Dentry::new_root(Arc::clone(&i));
    let fd = crate::file::install_open_at(&t, Arc::clone(&i), d,
        OpenFlags::O_RDWR | OpenFlags::O_CLOEXEC, 0, crate::FileCred::root(), usize::MAX, None).unwrap();
    assert!(t.cloexec(fd).unwrap());
    assert!(!t.get(fd).unwrap().flags().contains(OpenFlags::O_CLOEXEC));
    assert!(t.get(fd).unwrap().flags().contains(OpenFlags::O_RDWR));
}

#[test]
fn install_open_o_tmpfile_does_not_require_directory_inode() {
    let t = FdTable::new();
    let i: InodeRef = MemFile::new(3);
    let d = Dentry::new_root(Arc::clone(&i));
    let fd = crate::file::install_open_at(&t, Arc::clone(&i), d,
        OpenFlags::O_RDWR | OpenFlags::O_TMPFILE, 0, crate::FileCred::root(), usize::MAX, None).unwrap();
    let flags = t.get(fd).unwrap().flags();
    assert!(flags.contains(OpenFlags::O_TMPFILE));
    assert!(flags.contains(OpenFlags::O_DIRECTORY));
}

#[test]
fn fdtable_bitmap_alloc_min_skips_full_words() {
    let t = FdTable::new();
    let mut fds = alloc::vec::Vec::new();
    for _ in 0..70 { fds.push(t.alloc(mk_file()).unwrap()); }
    assert_eq!(fds.last().copied(), Some(69));
    t.close(3).unwrap();
    assert_eq!(t.alloc(mk_file()).unwrap(), 3);
    assert_eq!(t.dup_min(0, 70).unwrap(), 70);
}

#[test]
fn fdtable_flush_fires_on_close() {
    use core::sync::atomic::{AtomicUsize, Ordering as O};
    static FLUSHED: AtomicUsize = AtomicUsize::new(0);
    struct FlushOps;
    impl FileOps for FlushOps {
        fn read(&self, _i: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
        fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
        fn on_flush(&self, _i: &Inode) -> KResult<()> { FLUSHED.fetch_add(1, O::Relaxed); Ok(()) }
    }
    FLUSHED.store(0, O::Relaxed);
    let i: InodeRef = InodeBuilder::new(9, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(FlushOps)).build();
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(i, d, OpenFlags::O_RDWR);
    let t = FdTable::new();
    let a = t.alloc(f).unwrap();
    let b = t.dup(a).unwrap();
    t.close(a).unwrap();
    t.close(b).unwrap();
    assert_eq!(FLUSHED.load(O::Relaxed), 2);
}

#[test]
fn fdtable_close_returns_flush_error_after_removing_fd() {
    struct FlushErrOps;
    impl FileOps for FlushErrOps {
        fn on_flush(&self, _i: &Inode) -> KResult<()> { Err(VfsError::Eio) }
    }
    let i: InodeRef = InodeBuilder::new(10, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(FlushErrOps)).build();
    let d = Dentry::new_root(Arc::clone(&i));
    let t = FdTable::new();
    let fd = t.alloc(File::new(i, d, OpenFlags::O_RDWR)).unwrap();
    assert_eq!(t.close(fd), Err(VfsError::Eio));
    assert_eq!(t.close(fd), Err(VfsError::Ebadf), "Linux removes fd before returning flush errno");
}

#[test]
fn fdtable_close_flushes_snapshotted_file_ops() {
    use core::sync::atomic::{AtomicUsize, Ordering as O};
    static INODE_FLUSH: AtomicUsize = AtomicUsize::new(0);
    static FILE_FLUSH: AtomicUsize = AtomicUsize::new(0);
    struct InodeOps;
    impl FileOps for InodeOps {
        fn on_flush(&self, _i: &Inode) -> KResult<()> { INODE_FLUSH.fetch_add(1, O::Relaxed); Ok(()) }
    }
    struct FileOnlyOps;
    impl FileOps for FileOnlyOps {
        fn on_flush_file(&self, _f: &File) -> KResult<()> { FILE_FLUSH.fetch_add(1, O::Relaxed); Ok(()) }
    }
    INODE_FLUSH.store(0, O::Relaxed);
    FILE_FLUSH.store(0, O::Relaxed);
    let i: InodeRef = InodeBuilder::new(11, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(InodeOps)).build();
    let d = Dentry::new_root(Arc::clone(&i));
    let t = FdTable::new();
    let fd = t.alloc(File::new_at_fop(i, d, OpenFlags::O_RDWR, 0, crate::FileCred::root(), Arc::new(FileOnlyOps))).unwrap();
    t.close(fd).unwrap();
    assert_eq!(FILE_FLUSH.load(O::Relaxed), 1);
    assert_eq!(INODE_FLUSH.load(O::Relaxed), 0);
}

struct RwCapType;
impl FileSystemType for RwCapType {
    fn name(&self) -> &str { "rwcap" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> {
        unreachable!("file_fd tests construct superblocks directly")
    }
}

fn rwcap_sb(dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(RwCapType),
        Arc::new(SimpleSuperOps { magic: 0xCA9, block_size: 4096, options: String::new() }),
        0xCA9, dev, 4096, "rwcap".into(), Arc::new(()))
}

#[test]
fn file_write_straddling_s_maxbytes_is_clamped_before_backend() {
    use core::sync::atomic::{AtomicUsize, Ordering as O};
    static LAST_LEN: AtomicUsize = AtomicUsize::new(usize::MAX);
    struct LenOps;
    impl FileOps for LenOps {
        fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
            LAST_LEN.store(b.len(), O::Relaxed);
            Ok(b.len())
        }
    }
    let sb = rwcap_sb(1);
    let i: InodeRef = InodeBuilder::new(10, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(LenOps)).sb(Arc::downgrade(&sb)).build();
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(i, d, OpenFlags::O_WRONLY);
    f.set_pos(sb.s_maxbytes() - 3);
    LAST_LEN.store(usize::MAX, O::Relaxed);
    assert_eq!(f.write(b"abcdef").unwrap(), 3);
    assert_eq!(LAST_LEN.load(O::Relaxed), 3);
    assert_eq!(f.pos(), sb.s_maxbytes());
}

#[test]
fn file_write_at_s_maxbytes_returns_efbig_without_backend_call() {
    use core::sync::atomic::{AtomicUsize, Ordering as O};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    struct CountOps;
    impl FileOps for CountOps {
        fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
            CALLS.fetch_add(1, O::Relaxed);
            Ok(b.len())
        }
    }
    let sb = rwcap_sb(2);
    let i: InodeRef = InodeBuilder::new(11, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(CountOps)).sb(Arc::downgrade(&sb)).build();
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(i, d, OpenFlags::O_WRONLY);
    f.set_pos(sb.s_maxbytes());
    CALLS.store(0, O::Relaxed);
    assert_eq!(f.write(b"x"), Err(VfsError::Efbig));
    assert_eq!(CALLS.load(O::Relaxed), 0);
    assert_eq!(f.pos(), sb.s_maxbytes());
}
