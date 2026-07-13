use crate::inode::Inode;
use crate::superblock::SuperBlock;
use crate::types::KResult;
use core::any::Any;

use super::dquot::{Dquot, DquotRef};
use super::ids::Kqid;
use super::ids::QuotaType;
use super::limits::MemDqinfo;

/// One Linux `qc_type_state` snapshot. # C: O(1)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaTypeState {
    pub accounting: bool,
    pub enforcement: bool,
    pub info:       MemDqinfo,
    pub file:       QuotaFileStat,
    pub incoredqs:  u32,
}

/// Linux `qc_state` snapshot exported by `s_qcop->get_state`. # C: O(1)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaState {
    pub types: [QuotaTypeState; 3],
}

/// Quota-file state exported through Linux `qc_type_state`. # C: O(1)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaFileStat {
    pub ino:      u64,
    pub blocks:   u64,
    pub nextents: u32,
}

/// Filesystem quota hooks (`struct dquot_operations`). # C: FS-dependent
pub trait DquotOperations: Send + Sync {
    /// Downcast support for filesystem-private quota operations. # C: O(1)
    fn as_any(&self) -> &dyn Any;
    /// Allocate an in-core dquot object for `qid`. # C: FS-dependent
    fn alloc_dquot(&self, qid: Kqid) -> DquotRef { Dquot::new(qid) }
    /// Acquire/load a dquot before it is attached. # C: FS-dependent
    fn acquire_dquot(&self, _dq: &Dquot) -> KResult<()> { Ok(()) }
    /// Release a dquot after the filesystem drops it. # C: FS-dependent
    fn release_dquot(&self, _dq: &Dquot) -> KResult<()> { Ok(()) }
    /// Read the lowest persistent quota id at or after `qid.id`. # C: FS-dependent
    fn get_next_id(&self, _qid: Kqid) -> KResult<Option<Kqid>> { Err(crate::types::VfsError::Enosys) }
    /// Mark a dquot dirty after in-core counter mutation. # C: FS-dependent
    fn mark_dirty(&self, _dq: &Dquot) -> KResult<()> { Ok(()) }
    /// Persist a dirty dquot. # C: FS-dependent
    fn write_dquot(&self, _dq: &Dquot) -> KResult<()> { Ok(()) }
    /// Persist quota-file information for one class. # C: FS-dependent
    fn write_info(&self, _kind: QuotaType, _info: MemDqinfo) -> KResult<()> { Ok(()) }
    /// `s_qcop->get_state`: snapshot filesystem quota state for Q_XGETQSTAT*.
    /// # C: FS-dependent
    fn get_state(&self, sb: &SuperBlock) -> KResult<QuotaState> {
        Ok(QuotaState { types: core::array::from_fn(|idx| {
            let kind = QuotaType::from_slot(idx);
            let ops = sb.s_dquot.operations(kind);
            let file = ops.and_then(|o| o.file_stat(kind).ok()).unwrap_or_default();
            QuotaTypeState {
                accounting: sb.s_dquot.is_enabled(kind),
                enforcement: sb.s_dquot.is_enforced(kind),
                info: sb.s_dquot.info(kind),
                file,
                incoredqs: sb.s_dquot.dquots().by_kind(kind).len() as u32,
            }
        }) })
    }
    /// Snapshot quota-file inode state for Q_XGETQSTAT*. # C: FS-dependent
    fn file_stat(&self, _kind: QuotaType) -> KResult<QuotaFileStat> { Ok(QuotaFileStat::default()) }
    /// Free quota-file information after one class is fully disabled. # C: FS-dependent
    fn free_file_info(&self, _kind: QuotaType) -> KResult<()> { Ok(()) }
    /// Filesystem-specific inode initialization hook. # C: FS-dependent
    fn initialize(&self, _inode: &Inode) -> KResult<()> { Ok(()) }
}
