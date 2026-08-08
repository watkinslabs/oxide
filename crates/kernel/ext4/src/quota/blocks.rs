// Quota-file byte I/O. The bytes of a quota file are METADATA: every touched
// block is journalled inside a transaction, so a crash either replays the
// whole dquot commit (record + qtree links + file header) or none of it.

extern crate alloc;
use alloc::vec::Vec;

use crate::inode::Inode;
use crate::mount::{Mount, MountError};

use super::backend::{Qinfo, QBLK_BITS, QBLK_SIZE, V2_DQINFOOFF, map_mount};

/// Run `f` as one journalled transaction. Mirrors the Linux ext4 shape where a
/// dquot commit runs inside a single handle: nested quota writes join the open
/// transaction and commit together, so a crash cannot expose a qtree that is
/// half-linked against a file header that does not know about it.
/// # C: cost of `f` + one journal commit
pub(super) fn journaled<R>(m: &Mount, f: impl FnOnce() -> vfs::KResult<R>) -> vfs::KResult<R> {
    m.run_journaled(|_| f().map_err(MountError::Quota)).map_err(map_mount)
}

/// Shadow-aware quota-file block read: a read inside an open transaction must
/// see that transaction's own staged quota bytes, or a read-modify-write of a
/// qtree block already touched by the same operation reverts it. An unmapped
/// block inside `i_size` still reads as zeros (sparse-file semantics).
fn read_qfile_block(m: &Mount, inode: &Inode, file_blk: u32) -> Result<Vec<u8>, MountError> {
    match m.read_file_block_meta(inode, file_blk) {
        Ok(b) => Ok(b),
        Err(MountError::NotFound) => Ok(alloc::vec![0u8; m.sb.block_size as usize]),
        Err(e) => Err(e),
    }
}

pub(super) fn read_file_bytes(m: &Mount, inode: &Inode, off: u64, len: usize) -> vfs::KResult<Vec<u8>> {
    if off >= inode.size { return Ok(alloc::vec![0u8; len]); }
    let mut out = Vec::with_capacity(len);
    let bs = m.sb.block_size as u64;
    let mut pos = off;
    while out.len() < len {
        let file_blk = (pos / bs) as u32;
        let blk = read_qfile_block(m, inode, file_blk).map_err(map_mount)?;
        let in_blk = (pos % bs) as usize;
        let take = core::cmp::min(len - out.len(), blk.len() - in_blk);
        out.extend_from_slice(&blk[in_blk..in_blk + take]);
        pos += take as u64;
    }
    Ok(out)
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

/// Write `data` at byte offset `off` of the quota file at `ino`.
///
/// Growing the file first allocates + extends (itself a journalled metadata
/// change), then the same range is staged through the transaction so the new
/// block's CONTENT is in the log too. A raw data write here would leave the
/// accounted-for change replayed from the log and the accounting itself lost.
fn write_file_bytes_inner(m: &Mount, ino: u32, inode: &Inode, end: u64, off: u64, data: &[u8]) -> Result<(), MountError> {
    if end > inode.size {
        m.write_at(ino, off, data)?;
        let grown = m.read_inode(ino)?;
        return stage_file_bytes(m, &grown, off, data);
    }
    stage_file_bytes(m, inode, off, data)
}

fn stage_file_bytes(m: &Mount, inode: &Inode, off: u64, data: &[u8]) -> Result<(), MountError> {
    let bs = m.sb.block_size as u64;
    let mut pos = off;
    let mut done = 0usize;
    while done < data.len() {
        let file_blk = (pos / bs) as u32;
        let mut blk = read_qfile_block(m, inode, file_blk)?;
        let in_blk = (pos % bs) as usize;
        let take = core::cmp::min(data.len() - done, blk.len() - in_blk);
        blk[in_blk..in_blk + take].copy_from_slice(&data[done..done + take]);
        m.write_file_block_meta(inode, file_blk, &blk)?;
        pos += take as u64;
        done += take;
    }
    Ok(())
}

pub(super) fn write_file_bytes(m: &Mount, ino: u32, inode: &Inode, off: u64, data: &[u8]) -> vfs::KResult<()> {
    let end = off.checked_add(data.len() as u64).ok_or(vfs::VfsError::Efbig)?;
    m.run_journaled(|m| write_file_bytes_inner(m, ino, inode, end, off, data)).map_err(map_mount)
}

/// `dqi_bgrace`/`dqi_igrace` + the qtree free-list header of the quota file.
const QINFO_LEN: usize = 24;
const QINFO_OFF_BGRACE:     usize = 0;
const QINFO_OFF_IGRACE:     usize = 4;
const QINFO_OFF_FLAGS:      usize = 8;
const QINFO_OFF_BLOCKS:     usize = 12;
const QINFO_OFF_FREE_BLK:   usize = 16;
const QINFO_OFF_FREE_ENTRY: usize = 20;

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
    let mut buf = [0u8; QINFO_LEN];
    buf[QINFO_OFF_BGRACE..QINFO_OFF_BGRACE + 4].copy_from_slice(&(info.dqi_bgrace as u32).to_le_bytes());
    buf[QINFO_OFF_IGRACE..QINFO_OFF_IGRACE + 4].copy_from_slice(&(info.dqi_igrace as u32).to_le_bytes());
    buf[QINFO_OFF_FLAGS..QINFO_OFF_FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());
    buf[QINFO_OFF_BLOCKS..QINFO_OFF_BLOCKS + 4].copy_from_slice(&qi.blocks.to_le_bytes());
    buf[QINFO_OFF_FREE_BLK..QINFO_OFF_FREE_BLK + 4].copy_from_slice(&qi.free_blk.to_le_bytes());
    buf[QINFO_OFF_FREE_ENTRY..QINFO_OFF_FREE_ENTRY + 4].copy_from_slice(&qi.free_entry.to_le_bytes());
    write_file_bytes(m, ino, inode, V2_DQINFOOFF, &buf)
}
