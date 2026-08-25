use super::*;

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

