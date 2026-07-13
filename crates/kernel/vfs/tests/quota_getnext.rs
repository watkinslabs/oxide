use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{Dquot, DquotOperations, Kqid, KResult, MemDqblk, QuotaType, VfsError, quota_getnextquota, quota_off, quota_on, quota_setquota};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "quotagetnext" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

#[derive(Default)]
struct IterOps {
    next:     AtomicUsize,
    hits:     AtomicUsize,
    acquires: AtomicUsize,
}

impl DquotOperations for IterOps {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn acquire_dquot(&self, _dq: &Dquot) -> KResult<()> {
        self.acquires.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn get_next_id(&self, qid: Kqid) -> KResult<Option<Kqid>> {
        self.hits.fetch_add(1, Ordering::SeqCst);
        let id = self.next.load(Ordering::SeqCst) as u32;
        if id == 0 { Ok(None) } else { Ok(Some(Kqid { kind: qid.kind, id })) }
    }
}

struct NoNextOps;
impl DquotOperations for NoNextOps {
    fn as_any(&self) -> &dyn core::any::Any { self }
}

struct WrongKindOps;
impl DquotOperations for WrongKindOps {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn get_next_id(&self, _qid: Kqid) -> KResult<Option<Kqid>> { Ok(Some(Kqid::group(77))) }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0x5155, 0x4E58, 4096, "quotagetnext".into(), Arc::new(()))
}

#[test]
fn getnext_does_not_scan_resident_cache_without_backend_iterator() {
    let sb = sb();
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(NoNextOps)).unwrap();
    quota_setquota(&sb, Kqid::user(10), MemDqblk { dqb_curspace: 10, ..MemDqblk::new() }).unwrap();

    assert_eq!(quota_getnextquota(&sb, Kqid::user(1)), Err(VfsError::Enosys));
}

#[test]
fn getnext_uses_filesystem_next_id_then_dqget() {
    let sb = sb();
    let ops = Arc::new(IterOps::default());
    ops.next.store(30, Ordering::SeqCst);
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_setquota(&sb, Kqid::user(10), MemDqblk { dqb_curspace: 10, ..MemDqblk::new() }).unwrap();

    let (qid, dqblk) = quota_getnextquota(&sb, Kqid::user(1)).unwrap();

    assert_eq!(qid, Kqid::user(30));
    assert_eq!(dqblk, MemDqblk::new());
    assert_eq!(ops.hits.load(Ordering::SeqCst), 1);
    assert!(ops.acquires.load(Ordering::SeqCst) >= 1, "dqget materialized the backend-selected id");
}

#[test]
fn getnext_backend_no_next_is_enoent() {
    let sb = sb();
    let ops = Arc::new(IterOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();

    assert_eq!(quota_getnextquota(&sb, Kqid::user(1)), Err(VfsError::Enoent));
    assert_eq!(ops.hits.load(Ordering::SeqCst), 1);
}

#[test]
fn getnext_rejects_backend_kind_mismatch() {
    let sb = sb();
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(WrongKindOps)).unwrap();
    let group = Arc::new(IterOps::default());
    quota_on(&sb, QuotaType::Group, vfs::QFMT_VFS_V1, group.clone()).unwrap();

    assert_eq!(quota_getnextquota(&sb, Kqid::user(1)), Err(VfsError::Einval));
    assert_eq!(group.acquires.load(Ordering::SeqCst), 0);
    quota_off(&sb, QuotaType::User).unwrap();
    quota_off(&sb, QuotaType::Group).unwrap();
}
