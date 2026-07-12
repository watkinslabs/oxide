//! Linux `generic_write_check_limits` parity for the write family.
//! Scalar `write`, positional `pwrite`, and vectored `write_iter` all must
//! clamp writes that straddle `s_maxbytes` and return `EFBIG` only when no byte
//! can be written.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use vfs::{Dentry, File, FileOps, FileSystemType, FileType, Inode, InodeBuilder,
          InodeRef, KResult, OpenFlags, SimpleSuperOps, SuperBlock, VfsError,
          default_inode_ops, mk_mode};

static CALLS: AtomicUsize = AtomicUsize::new(0);
static LAST_LEN: AtomicUsize = AtomicUsize::new(usize::MAX);

struct CapType;
impl FileSystemType for CapType {
    fn name(&self) -> &str { "writecap" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> {
        unreachable!("test constructs superblocks directly")
    }
}

fn sb(dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(CapType),
        Arc::new(SimpleSuperOps { magic: 0xCA9, block_size: 4096, options: String::new() }),
        0xCA9, dev, 4096, "writecap".into(), Arc::new(()))
}

struct CapOps;
impl FileOps for CapOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let n = buf.len().min(1);
        if n != 0 { buf[0] = 0; }
        Ok(n)
    }
    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        CALLS.fetch_add(1, Ordering::Relaxed);
        LAST_LEN.store(buf.len(), Ordering::Relaxed);
        inode.set_size(off.saturating_add(buf.len() as u64));
        Ok(buf.len())
    }
}

fn reset_counters() {
    CALLS.store(0, Ordering::Relaxed);
    LAST_LEN.store(usize::MAX, Ordering::Relaxed);
}

fn file(dev: u64, flags: OpenFlags) -> (Arc<SuperBlock>, Arc<File>) {
    let sb = sb(dev);
    let inode: InodeRef = InodeBuilder::new(dev + 100, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(CapOps))
        .sb(Arc::downgrade(&sb))
        .build();
    let d = Dentry::new_root(Arc::clone(&inode));
    (sb, File::new(inode, d, flags))
}

#[test]
fn pwrite_straddling_s_maxbytes_is_clamped_before_backend() {
    let (sb, f) = file(1, OpenFlags::O_WRONLY);
    reset_counters();
    assert_eq!(f.pwrite(b"abcdef", (sb.s_maxbytes() - 2) as i64), Ok(2));
    assert_eq!(LAST_LEN.load(Ordering::Relaxed), 2);
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(f.pos(), 0, "pwrite must not advance f_pos");
}

#[test]
fn pwrite_at_s_maxbytes_returns_efbig_without_backend_call() {
    let (sb, f) = file(2, OpenFlags::O_WRONLY);
    reset_counters();
    assert_eq!(f.pwrite(b"x", sb.s_maxbytes() as i64), Err(VfsError::Efbig));
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
}

#[test]
fn write_iter_straddling_s_maxbytes_returns_partial_count() {
    let (sb, f) = file(3, OpenFlags::O_WRONLY);
    f.set_pos(sb.s_maxbytes() - 3);
    reset_counters();
    assert_eq!(f.write_iter(&[b"ab", b"cdef"]), Ok(3));
    assert_eq!(f.pos(), sb.s_maxbytes());
    assert_eq!(CALLS.load(Ordering::Relaxed), 2);
    assert_eq!(LAST_LEN.load(Ordering::Relaxed), 1);
}

#[test]
fn write_iter_at_s_maxbytes_returns_efbig_without_backend_call() {
    let (sb, f) = file(4, OpenFlags::O_WRONLY);
    f.set_pos(sb.s_maxbytes());
    reset_counters();
    assert_eq!(f.write_iter(&[b"x"]), Err(VfsError::Efbig));
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(f.pos(), sb.s_maxbytes());
}
