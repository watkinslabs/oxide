use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::Spinlock;

use crate::inode::Inode;
use crate::mount::{Mount, MountError};
use crate::rootfs::RootfsState;

use super::cleanup::clear_visible_quota_file;
use super::delete::delete_dquot;
use super::format::entry_size;
use super::insert::{insert_dquot, write_existing_dquot};
use super::scan::{next_tree_id, read_dquot_at};

pub(super) const USR_MAGIC: u32 = 0xd9c0_1f11;
pub(super) const GRP_MAGIC: u32 = 0xd9c0_1927;
pub(super) const PRJ_MAGIC: u32 = 0xd9c0_3f14;
const V2_VERSION_V1: u32 = 1;
const V2_VERSION_V0: u32 = 0;
pub(super) const V2_DQINFOOFF: u64 = 8;
pub(super) const QBLK_BITS: u32 = 10;
pub(super) const QBLK_SIZE: usize = 1 << QBLK_BITS;
pub(super) const QT_TREEOFF: u32 = 1;
pub(super) const QT_DQDBHEADER: usize = 16;
pub(super) const MAX_QTREE_DEPTH: usize = 6;
struct QuotaMapClass;
impl sync::LockClass for QuotaMapClass { fn rank() -> u16 { 35 } }

#[derive(Clone, Copy)]
pub(super) struct Qinfo {
    pub(super) blocks: u32,
    pub(super) free_blk: u32,
    pub(super) free_entry: u32,
    pub(super) depth: usize,
    pub(super) entry_size: usize,
}

pub(super) struct Ext4QuotaOps {
    st: Arc<RootfsState>,
    files: Spinlock<[u32; vfs::MAXQUOTAS], QuotaMapClass>,
    formats: Spinlock<[u32; vfs::MAXQUOTAS], QuotaMapClass>,
    hidden: Spinlock<[bool; vfs::MAXQUOTAS], QuotaMapClass>,
    visible_orig_flags: Spinlock<[u32; vfs::MAXQUOTAS], QuotaMapClass>,
    offsets: Spinlock<BTreeMap<vfs::Kqid, u64>, QuotaMapClass>,
}

impl Ext4QuotaOps {
    pub(super) fn new(st: Arc<RootfsState>) -> Self {
        Self { st, files: Spinlock::new([0; vfs::MAXQUOTAS]), formats: Spinlock::new([0; vfs::MAXQUOTAS]), hidden: Spinlock::new([false; vfs::MAXQUOTAS]), visible_orig_flags: Spinlock::new([0; vfs::MAXQUOTAS]), offsets: Spinlock::new(BTreeMap::new()) }
    }

    pub(super) fn set_file(&self, kind: vfs::QuotaType, ino: u32, fmt: u32, hidden: bool) {
        self.files.lock()[kind.slot()] = ino;
        self.formats.lock()[kind.slot()] = fmt;
        self.hidden.lock()[kind.slot()] = hidden;
        self.visible_orig_flags.lock()[kind.slot()] = 0;
    }

    pub(super) fn remember_visible_orig_flags(&self, kind: vfs::QuotaType, flags: u32) {
        self.visible_orig_flags.lock()[kind.slot()] = flags;
    }

    pub(super) fn remember_offset(&self, qid: vfs::Kqid, off: u64) {
        self.offsets.lock().insert(qid, off);
    }

    pub(super) fn has_active_file(&self, ino: u32) -> bool {
        self.files.lock().iter().any(|file_ino| *file_ino == ino)
    }

    pub(super) fn forget_file(&self, kind: vfs::QuotaType) {
        self.files.lock()[kind.slot()] = 0;
        self.formats.lock()[kind.slot()] = 0;
        self.hidden.lock()[kind.slot()] = false;
        self.visible_orig_flags.lock()[kind.slot()] = 0;
        self.offsets.lock().retain(|qid, _| qid.kind != kind);
    }

    fn clear_file(&self, kind: vfs::QuotaType) -> vfs::KResult<()> {
        let ino = self.files.lock()[kind.slot()];
        let hidden = self.hidden.lock()[kind.slot()];
        let orig_flags = self.visible_orig_flags.lock()[kind.slot()];
        if ino != 0 && !hidden { clear_visible_quota_file(&self.st, ino, orig_flags)?; }
        self.files.lock()[kind.slot()] = 0;
        self.hidden.lock()[kind.slot()] = false;
        self.formats.lock()[kind.slot()] = 0;
        self.visible_orig_flags.lock()[kind.slot()] = 0;
        self.offsets.lock().retain(|qid, _| qid.kind != kind);
        Ok(())
    }

    fn file_ino(&self, kind: vfs::QuotaType) -> vfs::KResult<u32> {
        let ino = self.files.lock()[kind.slot()];
        if ino != 0 { Ok(ino) } else { quota_ino(&self.st.mount, kind) }
    }

    fn file_fmt(&self, kind: vfs::QuotaType) -> vfs::KResult<u32> {
        let fmt = self.formats.lock()[kind.slot()];
        if fmt != 0 { Ok(fmt) } else { Err(vfs::VfsError::Einval) }
    }

    fn rollback_inserted_dquot(&self, ino: u32, mut qi: Qinfo, info: vfs::MemDqinfo, qid: vfs::Kqid, off: u64) -> vfs::KResult<()> {
        let rb_inode = read_quota_inode(&self.st.mount, ino)?;
        delete_dquot(&self.st.mount, ino, &rb_inode, &mut qi, qid, off)?;
        write_qinfo(&self.st.mount, ino, &rb_inode, &qi, info)
    }

    fn rollback_released_dquot(&self, ino: u32, mut qi: Qinfo, info: vfs::MemDqinfo, dq: &vfs::Dquot) -> vfs::KResult<u64> {
        let rb_inode = read_quota_inode(&self.st.mount, ino)?;
        let off = insert_dquot(&self.st.mount, ino, &rb_inode, &mut qi, dq.id())?;
        write_existing_dquot(&self.st.mount, &rb_inode, off, dq.id().id, dq.dqblk(), self.file_fmt(dq.id().kind)?)?;
        write_qinfo(&self.st.mount, ino, &rb_inode, &qi, info)?;
        Ok(off)
    }
}

impl vfs::DquotOperations for Ext4QuotaOps {
    fn as_any(&self) -> &dyn core::any::Any { self }

    fn acquire_dquot(&self, dq: &vfs::Dquot) -> vfs::KResult<()> {
        if self.offsets.lock().contains_key(&dq.id()) { return Ok(()); }
        let ino = self.file_ino(dq.id().kind)?;
        let fmt = self.file_fmt(dq.id().kind)?;
        let inode = read_quota_inode(&self.st.mount, ino)?;
        let qi = read_info(&self.st.mount, &inode, dq.id().kind, fmt)?;
        if let Some((off, blk)) = read_dquot_at(&self.st.mount, &inode, &qi, dq.id())? {
            self.offsets.lock().insert(dq.id(), off);
            dq.set_dqblk(blk);
        }
        Ok(())
    }

    fn mark_dirty(&self, dq: &vfs::Dquot) -> vfs::KResult<()> {
        #[cfg(not(target_os = "oxide-kernel"))]
        if self.st.mount.faults.next_quota_mark_dirty.swap(false, core::sync::atomic::Ordering::AcqRel) {
            return Err(vfs::VfsError::Eio);
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            let n = self.st.mount.faults.quota_mark_dirty_after.load(core::sync::atomic::Ordering::Acquire);
            if n != 0 {
                if n == 1 {
                    self.st.mount.faults.quota_mark_dirty_after.store(0, core::sync::atomic::Ordering::Release);
                    return Err(vfs::VfsError::Eio);
                }
                let _ = self.st.mount.faults.quota_mark_dirty_after.compare_exchange(
                    n, n - 1,
                    core::sync::atomic::Ordering::AcqRel,
                    core::sync::atomic::Ordering::Acquire,
                );
            }
        }
        dq.mark_dirty();
        Ok(())
    }

    fn write_dquot(&self, dq: &vfs::Dquot) -> vfs::KResult<()> {
        let ino = self.file_ino(dq.id().kind)?;
        let fmt = self.file_fmt(dq.id().kind)?;
        let inode = read_quota_inode(&self.st.mount, ino)?;
        let known = { self.offsets.lock().get(&dq.id()).copied() };
        let mut inserted = None;
        let off = match known {
            Some(o) => o,
            None => {
                let mut qi = read_info(&self.st.mount, &inode, dq.id().kind, fmt)?;
                let off = insert_dquot(&self.st.mount, ino, &inode, &mut qi, dq.id())?;
                let info = self.st.i_sb().map(|s| s.s_dquot.info(dq.id().kind)).unwrap_or_default();
                if let Err(e) = write_qinfo(&self.st.mount, ino, &inode, &qi, info) {
                    if let Err(rb) = self.rollback_inserted_dquot(ino, qi, info, dq.id(), off) { return Err(rb); }
                    return Err(e);
                }
                inserted = Some((qi, info));
                off
            }
        };
        let inode = read_quota_inode(&self.st.mount, ino)?;
        if let Err(e) = write_existing_dquot(&self.st.mount, &inode, off, dq.id().id, dq.dqblk(), fmt) {
            if let Some((qi, info)) = inserted {
                self.offsets.lock().remove(&dq.id());
                if let Err(rb) = self.rollback_inserted_dquot(ino, qi, info, dq.id(), off) { return Err(rb); }
            }
            return Err(e);
        }
        if inserted.is_some() { self.offsets.lock().insert(dq.id(), off); }
        Ok(())
    }

    fn write_info(&self, kind: vfs::QuotaType, info: vfs::MemDqinfo) -> vfs::KResult<()> {
        let ino = self.file_ino(kind)?;
        let fmt = self.file_fmt(kind)?;
        let inode = read_quota_inode(&self.st.mount, ino)?;
        let qi = read_info(&self.st.mount, &inode, kind, fmt)?;
        write_qinfo(&self.st.mount, ino, &inode, &qi, info)
    }

    fn file_stat(&self, kind: vfs::QuotaType) -> vfs::KResult<vfs::QuotaFileStat> {
        let ino = self.file_ino(kind)?;
        let inode = read_quota_inode(&self.st.mount, ino)?;
        let nextents = self.st.mount.collect_phys_extents(&inode.i_block).map_err(map_mount)?.len() as u32;
        Ok(vfs::QuotaFileStat { ino: ino as u64, blocks: inode.i_blocks, nextents })
    }

    fn free_file_info(&self, kind: vfs::QuotaType) -> vfs::KResult<()> {
        self.clear_file(kind)
    }

    fn release_dquot(&self, dq: &vfs::Dquot) -> vfs::KResult<()> {
        if !releasable_fake(dq) { return Ok(()); }
        let off = match self.offsets.lock().get(&dq.id()).copied() {
            Some(o) => o,
            None => return Ok(()),
        };
        let ino = self.file_ino(dq.id().kind)?;
        let fmt = self.file_fmt(dq.id().kind)?;
        let inode = read_quota_inode(&self.st.mount, ino)?;
        let mut qi = read_info(&self.st.mount, &inode, dq.id().kind, fmt)?;
        delete_dquot(&self.st.mount, ino, &inode, &mut qi, dq.id(), off)?;
        let info = self.st.i_sb().map(|s| s.s_dquot.info(dq.id().kind)).unwrap_or_default();
        if let Err(e) = write_qinfo(&self.st.mount, ino, &inode, &qi, info) {
            match self.rollback_released_dquot(ino, qi, info, dq) {
                Ok(rb_off) => {
                    self.offsets.lock().insert(dq.id(), rb_off);
                    return Err(e);
                }
                Err(rb) => {
                    self.offsets.lock().insert(dq.id(), off);
                    return Err(rb);
                }
            }
        }
        self.offsets.lock().remove(&dq.id());
        Ok(())
    }

    fn get_next_id(&self, qid: vfs::Kqid) -> vfs::KResult<Option<vfs::Kqid>> {
        let ino = self.file_ino(qid.kind)?;
        let fmt = self.file_fmt(qid.kind)?;
        let inode = read_quota_inode(&self.st.mount, ino)?;
        let qi = read_info(&self.st.mount, &inode, qid.kind, fmt)?;
        next_tree_id(&self.st.mount, &inode, &qi, qid.kind, qid.id)
    }
}

pub(super) fn ops_as_ext4(_ops: &dyn vfs::DquotOperations) -> Option<&Ext4QuotaOps> {
    _ops.as_any().downcast_ref::<Ext4QuotaOps>()
}

pub(super) fn quota_ino(m: &Mount, kind: vfs::QuotaType) -> vfs::KResult<u32> {
    let ino = match kind {
        vfs::QuotaType::User => m.sb.usr_quota_inum,
        vfs::QuotaType::Group => m.sb.grp_quota_inum,
        vfs::QuotaType::Project => m.sb.prj_quota_inum,
    };
    if ino == 0 { return Err(vfs::VfsError::Eperm); }
    if !valid_quota_ino(kind, ino) { return Err(vfs::VfsError::Euclean); }
    Ok(ino)
}

fn valid_quota_ino(kind: vfs::QuotaType, ino: u32) -> bool {
    match kind {
        vfs::QuotaType::User => ino == super::ids::USR_QUOTA_INO,
        vfs::QuotaType::Group => ino == super::ids::GRP_QUOTA_INO,
        vfs::QuotaType::Project => ino >= super::ids::GOOD_OLD_FIRST_INO,
    }
}

pub(super) fn read_quota_inode(m: &Mount, ino: u32) -> vfs::KResult<Inode> {
    m.read_inode(ino).map_err(map_mount)
}

pub(super) fn map_mount(e: MountError) -> vfs::VfsError {
    match e {
        MountError::Quota(e) => e,
        MountError::NoSpace => vfs::VfsError::Enospc,
        MountError::NotFound => vfs::VfsError::Enoent,
        MountError::UnsupportedFeature => vfs::VfsError::Einval,
        _ => vfs::VfsError::Eio,
    }
}

pub(super) fn read_file_bytes(m: &Mount, inode: &Inode, off: u64, len: usize) -> vfs::KResult<Vec<u8>> {
    if off >= inode.size { return Ok(alloc::vec![0u8; len]); }
    let mut out = Vec::with_capacity(len);
    let bs = m.sb.block_size as u64;
    let mut pos = off;
    while out.len() < len {
        let file_blk = (pos / bs) as u32;
        let blk = m.read_file_block(inode, file_blk).map_err(map_mount)?;
        let in_blk = (pos % bs) as usize;
        let take = core::cmp::min(len - out.len(), blk.len() - in_blk);
        out.extend_from_slice(&blk[in_blk..in_blk + take]);
        pos += take as u64;
    }
    Ok(out)
}

pub(super) fn read_info(m: &Mount, inode: &Inode, kind: vfs::QuotaType, fmt: u32) -> vfs::KResult<Qinfo> {
    let hdr = read_file_bytes(m, inode, 0, 8)?;
    if le32(&hdr, 0) != magic(kind) { return Err(vfs::VfsError::Einval); }
    let version = match fmt {
        vfs::QFMT_VFS_V0 => V2_VERSION_V0,
        vfs::QFMT_VFS_V1 => V2_VERSION_V1,
        _ => return Err(vfs::VfsError::Einval),
    };
    if le32(&hdr, 4) != version { return Err(vfs::VfsError::Einval); }
    let buf = read_file_bytes(m, inode, V2_DQINFOOFF, 24)?;
    let blocks = le32(&buf, 12);
    let free_blk = le32(&buf, 16);
    let free_entry = le32(&buf, 20);
    if ((blocks as u64) << QBLK_BITS) > inode.size { return Err(vfs::VfsError::Eio); }
    if free_blk != 0 && (free_blk <= QT_TREEOFF || free_blk >= blocks) { return Err(vfs::VfsError::Eio); }
    if free_entry != 0 && (free_entry <= QT_TREEOFF || free_entry >= blocks) { return Err(vfs::VfsError::Eio); }
    Ok(Qinfo { blocks, free_blk, free_entry, depth: qtree_depth(), entry_size: entry_size(fmt)? })
}

pub(super) fn detect_format(m: &Mount, inode: &Inode, kind: vfs::QuotaType) -> vfs::KResult<u32> {
    let hdr = read_file_bytes(m, inode, 0, 8)?;
    if le32(&hdr, 0) != magic(kind) { return Err(vfs::VfsError::Einval); }
    match le32(&hdr, 4) {
        V2_VERSION_V0 => Ok(vfs::QFMT_VFS_V0),
        V2_VERSION_V1 => Ok(vfs::QFMT_VFS_V1),
        _ => Err(vfs::VfsError::Einval),
    }
}

pub(super) fn read_file_info(m: &Mount, inode: &Inode) -> vfs::KResult<vfs::MemDqinfo> {
    let buf = read_file_bytes(m, inode, V2_DQINFOOFF, 24)?;
    Ok(vfs::MemDqinfo {
        dqi_bgrace: le32(&buf, 0) as u64,
        dqi_igrace: le32(&buf, 4) as u64,
        dqi_rt_bgrace: 0,
        dqi_bwarnlimit: 0,
        dqi_iwarnlimit: 0,
        dqi_rtbwarnlimit: 0,
        dqi_flags: 0,
        dqi_valid: vfs::IIF_BGRACE | vfs::IIF_IGRACE | vfs::IIF_FLAGS,
    })
}

pub(super) fn read_qblk(m: &Mount, inode: &Inode, blk: u32) -> vfs::KResult<Vec<u8>> {
    read_file_bytes(m, inode, (blk as u64) << QBLK_BITS, QBLK_SIZE)
}

pub(super) fn write_qblk(m: &Mount, ino: u32, inode: &Inode, blk: u32, buf: &[u8]) -> vfs::KResult<()> {
    if buf.len() != QBLK_SIZE { return Err(vfs::VfsError::Einval); }
    #[cfg(not(target_os = "oxide-kernel"))]
    if m.faults.next_quota_qblk_write.swap(false, core::sync::atomic::Ordering::AcqRel) { return Err(vfs::VfsError::Eio); }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        let n = m.faults.quota_qblk_write_after.load(core::sync::atomic::Ordering::Acquire);
        if n != 0 {
            if n == 1 {
                m.faults.quota_qblk_write_after.store(0, core::sync::atomic::Ordering::Release);
                return Err(vfs::VfsError::Eio);
            }
            let _ = m.faults.quota_qblk_write_after.compare_exchange(
                n, n - 1,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            );
        }
    }
    write_file_bytes(m, ino, inode, (blk as u64) << QBLK_BITS, buf)
}

pub(super) fn write_file_bytes(m: &Mount, ino: u32, inode: &Inode, off: u64, data: &[u8]) -> vfs::KResult<()> {
    let end = off.checked_add(data.len() as u64).ok_or(vfs::VfsError::Efbig)?;
    if end > inode.size {
        return m.write_at(ino, off, data).map_err(map_mount);
    }
    let bs = m.sb.block_size as u64;
    let mut pos = off;
    let mut done = 0usize;
    while done < data.len() {
        let file_blk = (pos / bs) as u32;
        let mut blk = m.read_file_block(inode, file_blk).map_err(map_mount)?;
        let in_blk = (pos % bs) as usize;
        let take = core::cmp::min(data.len() - done, blk.len() - in_blk);
        blk[in_blk..in_blk + take].copy_from_slice(&data[done..done + take]);
        m.write_file_block(inode, file_blk, &blk).map_err(map_mount)?;
        pos += take as u64;
        done += take;
    }
    Ok(())
}

pub(super) fn write_qinfo(m: &Mount, ino: u32, inode: &Inode, qi: &Qinfo, info: vfs::MemDqinfo) -> vfs::KResult<()> {
    #[cfg(not(target_os = "oxide-kernel"))]
    if m.faults.next_quota_info_write.swap(false, core::sync::atomic::Ordering::AcqRel) { return Err(vfs::VfsError::Eio); }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        let n = m.faults.quota_info_write_after.load(core::sync::atomic::Ordering::Acquire);
        if n != 0 {
            if n == 1 {
                m.faults.quota_info_write_after.store(0, core::sync::atomic::Ordering::Release);
                return Err(vfs::VfsError::Eio);
            }
            let _ = m.faults.quota_info_write_after.compare_exchange(
                n, n - 1,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            );
        }
    }
    let mut buf = [0u8; 24];
    buf[0..4].copy_from_slice(&(info.dqi_bgrace as u32).to_le_bytes());
    buf[4..8].copy_from_slice(&(info.dqi_igrace as u32).to_le_bytes());
    buf[8..12].copy_from_slice(&0u32.to_le_bytes());
    buf[12..16].copy_from_slice(&qi.blocks.to_le_bytes());
    buf[16..20].copy_from_slice(&qi.free_blk.to_le_bytes());
    buf[20..24].copy_from_slice(&qi.free_entry.to_le_bytes());
    write_file_bytes(m, ino, inode, V2_DQINFOOFF, &buf)
}

fn releasable_fake(dq: &vfs::Dquot) -> bool {
    let dqblk = dq.dqblk();
    dq.is_fake() && dqblk.dqb_curspace == 0 && dqblk.dqb_curinodes == 0
}

fn qtree_depth() -> usize { 4 }
pub(super) fn entries_per_blk(qi: &Qinfo) -> usize { (QBLK_SIZE - QT_DQDBHEADER) / qi.entry_size }
pub(super) fn qindex(id: u32, depth: usize) -> usize {
    let mut div = qtree_depth() - depth - 1;
    let mut n = id;
    while div > 0 { n /= 256; div -= 1; }
    (n % 256) as usize
}
fn magic(kind: vfs::QuotaType) -> u32 {
    match kind {
        vfs::QuotaType::User => USR_MAGIC,
        vfs::QuotaType::Group => GRP_MAGIC,
        vfs::QuotaType::Project => PRJ_MAGIC,
    }
}
pub(super) fn entry_unused(buf: &[u8]) -> bool { buf.iter().all(|b| *b == 0) }
pub(super) fn put16(buf: &mut [u8], off: usize, val: u16) { buf[off..off + 2].copy_from_slice(&val.to_le_bytes()); }
pub(super) fn put32(buf: &mut [u8], off: usize, val: u32) { buf[off..off + 4].copy_from_slice(&val.to_le_bytes()); }
pub(super) fn le16(buf: &[u8], off: usize) -> u16 { u16::from_le_bytes([buf[off], buf[off + 1]]) }
pub(super) fn le32(buf: &[u8], off: usize) -> u32 { u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releasable_fake_matches_linux_predicate() {
        let dq = vfs::Dquot::new(vfs::Kqid::user(1000));
        dq.set_dqblk(vfs::MemDqblk { dqb_rsvspace: 4096, ..vfs::MemDqblk::new() });
        assert!(releasable_fake(dq.as_ref()));
        dq.set_dqblk(vfs::MemDqblk { dqb_bhardlimit: 8192, ..vfs::MemDqblk::new() });
        assert!(!releasable_fake(dq.as_ref()));
        dq.set_dqblk(vfs::MemDqblk { dqb_curspace: 1, ..vfs::MemDqblk::new() });
        assert!(!releasable_fake(dq.as_ref()));
    }
}
