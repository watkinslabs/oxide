use crate::inode::Inode;
use crate::mount::Mount;

use super::backend::{write_file_bytes, MAX_QTREE_DEPTH, QBLK_BITS, QBLK_SIZE, QT_DQDBHEADER, QT_TREEOFF, Qinfo, entries_per_blk, entry_unused, le16, le32, put16, put32, qindex, read_qblk, write_qblk};
use super::format::{entry_size, mem_to_disk};

pub(super) fn insert_dquot(m: &Mount, ino: u32, inode: &Inode, qi: &mut Qinfo, qid: vfs::Kqid) -> vfs::KResult<u64> {
    if qi.blocks <= QT_TREEOFF || qi.depth >= MAX_QTREE_DEPTH { return Err(vfs::VfsError::Eio); }
    let mut blks = [0u32; MAX_QTREE_DEPTH];
    blks[0] = QT_TREEOFF;
    do_insert_tree(m, ino, inode, qi, qid.id, &mut blks, 0)
}

fn do_insert_tree(m: &Mount, ino: u32, inode: &Inode, qi: &mut Qinfo, id: u32, blks: &mut [u32; MAX_QTREE_DEPTH], depth: usize) -> vfs::KResult<u64> {
    let mut buf;
    let newact;
    if blks[depth] == 0 {
        let blk = get_free_qblk(m, ino, inode, qi)?;
        for used in blks.iter().take(depth) {
            if *used == blk { return Err(vfs::VfsError::Eio); }
        }
        blks[depth] = blk;
        buf = alloc::vec![0u8; QBLK_SIZE];
        newact = true;
    } else {
        buf = read_qblk(m, inode, blks[depth])?;
        newact = false;
    }
    let idx = qindex(id, depth);
    let next = le32(&buf, idx * 4);
    if next >= qi.blocks { return Err(vfs::VfsError::Eio); }
    if next != 0 {
        for used in blks.iter().take(depth + 1) {
            if *used == next { return Err(vfs::VfsError::Eio); }
        }
    }
    let newson = next == 0;
    blks[depth + 1] = next;
    let child = if depth + 1 == qi.depth {
        let off = if next != 0 {
            find_free_dqentry_in_blk(m, ino, inode, qi, next, id)?
        } else {
            find_free_dqentry(m, ino, inode, qi)?
        };
        blks[depth + 1] = (off >> QBLK_BITS) as u32;
        off
    } else {
        do_insert_tree(m, ino, inode, qi, id, blks, depth + 1)?
    };
    if newson {
        buf[idx * 4..idx * 4 + 4].copy_from_slice(&blks[depth + 1].to_le_bytes());
        write_qblk(m, ino, inode, blks[depth], &buf)?;
    }
    if newact && !newson { put_free_qblk(m, ino, inode, qi, blks[depth], &mut buf)?; }
    Ok(child)
}

fn get_free_qblk(m: &Mount, ino: u32, inode: &Inode, qi: &mut Qinfo) -> vfs::KResult<u32> {
    if qi.free_blk != 0 {
        let blk = qi.free_blk;
        let buf = read_qblk(m, inode, blk)?;
        check_dqdb_header(qi, &buf)?;
        qi.free_blk = le32(&buf, 0);
        return Ok(blk);
    }
    let blk = qi.blocks;
    let zero = alloc::vec![0u8; QBLK_SIZE];
    write_qblk(m, ino, inode, blk, &zero)?;
    qi.blocks = qi.blocks.checked_add(1).ok_or(vfs::VfsError::Efbig)?;
    Ok(blk)
}

fn put_free_qblk(m: &Mount, ino: u32, inode: &Inode, qi: &mut Qinfo, blk: u32, buf: &mut [u8]) -> vfs::KResult<()> {
    buf.fill(0);
    put32(buf, 0, qi.free_blk);
    put32(buf, 4, 0);
    put16(buf, 8, 0);
    write_qblk(m, ino, inode, blk, buf)?;
    qi.free_blk = blk;
    Ok(())
}

fn find_free_dqentry(m: &Mount, ino: u32, inode: &Inode, qi: &mut Qinfo) -> vfs::KResult<u64> {
    let blk;
    let mut buf;
    if qi.free_entry != 0 {
        blk = qi.free_entry;
        buf = read_qblk(m, inode, blk)?;
        check_dqdb_header(qi, &buf)?;
    } else {
        blk = get_free_qblk(m, ino, inode, qi)?;
        buf = alloc::vec![0u8; QBLK_SIZE];
        qi.free_entry = blk;
    }
    let entries = entries_per_blk(qi);
    let used = le16(&buf, 8);
    if used as usize + 1 >= entries {
        remove_free_dqentry(m, ino, inode, qi, blk, &mut buf)?;
    }
    put16(&mut buf, 8, used.checked_add(1).ok_or(vfs::VfsError::Eio)?);
    let mut slot = None;
    for i in 0..entries {
        let off = QT_DQDBHEADER + i * qi.entry_size;
        if entry_unused(&buf[off..off + qi.entry_size]) {
            slot = Some(i);
            break;
        }
    }
    let slot = slot.ok_or(vfs::VfsError::Eio)?;
    write_qblk(m, ino, inode, blk, &buf)?;
    Ok(((blk as u64) << QBLK_BITS) + QT_DQDBHEADER as u64 + (slot * qi.entry_size) as u64)
}

fn find_free_dqentry_in_blk(m: &Mount, ino: u32, inode: &Inode, qi: &mut Qinfo, blk: u32, id: u32) -> vfs::KResult<u64> {
    if blk <= QT_TREEOFF || blk >= qi.blocks { return Err(vfs::VfsError::Eio); }
    let mut buf = read_qblk(m, inode, blk)?;
    check_dqdb_header(qi, &buf)?;
    let entries = entries_per_blk(qi);
    let mut used = 0usize;
    let mut slot = None;
    for i in 0..entries {
        let off = QT_DQDBHEADER + i * qi.entry_size;
        let rec = &buf[off..off + qi.entry_size];
        if entry_unused(rec) {
            if slot.is_none() { slot = Some(i); }
            continue;
        }
        if le32(rec, 0) == id { return Err(vfs::VfsError::Eio); }
        used += 1;
    }
    let slot = slot.ok_or(vfs::VfsError::Enospc)?;
    put16(&mut buf, 8, used.checked_add(1).ok_or(vfs::VfsError::Eio)? as u16);
    if used + 1 >= entries && (qi.free_entry == blk || le32(&buf, 0) != 0 || le32(&buf, 4) != 0) {
        remove_free_dqentry(m, ino, inode, qi, blk, &mut buf)?;
    } else {
        write_qblk(m, ino, inode, blk, &buf)?;
    }
    Ok(((blk as u64) << QBLK_BITS) + QT_DQDBHEADER as u64 + (slot * qi.entry_size) as u64)
}

fn remove_free_dqentry(m: &Mount, ino: u32, inode: &Inode, qi: &mut Qinfo, blk: u32, buf: &mut [u8]) -> vfs::KResult<()> {
    let next = le32(buf, 0);
    let prev = le32(buf, 4);
    if next != 0 {
        let mut nbuf = read_qblk(m, inode, next)?;
        put32(&mut nbuf, 4, prev);
        write_qblk(m, ino, inode, next, &nbuf)?;
    }
    if prev != 0 {
        let mut pbuf = read_qblk(m, inode, prev)?;
        put32(&mut pbuf, 0, next);
        write_qblk(m, ino, inode, prev, &pbuf)?;
    } else {
        qi.free_entry = next;
    }
    put32(buf, 0, 0);
    put32(buf, 4, 0);
    write_qblk(m, ino, inode, blk, buf)
}

fn check_dqdb_header(qi: &Qinfo, buf: &[u8]) -> vfs::KResult<()> {
    if le32(buf, 0) >= qi.blocks { return Err(vfs::VfsError::Eio); }
    if le32(buf, 4) >= qi.blocks { return Err(vfs::VfsError::Eio); }
    if le16(buf, 8) as usize > entries_per_blk(qi) { return Err(vfs::VfsError::Eio); }
    Ok(())
}

/// Overwrite one id's record in place. The record is quota-file metadata, so it
/// is staged through the enclosing transaction rather than written straight to
/// its target: a crash after the transaction is published replays the record,
/// and a crash before it leaves the previous record whole.
pub(super) fn write_existing_dquot(m: &Mount, ino: u32, inode: &Inode, off: u64, id: u32, dq: vfs::MemDqblk, fmt: u32) -> vfs::KResult<()> {
    #[cfg(not(target_os = "oxide-kernel"))]
    if m.faults.next_quota_record_write.swap(false, core::sync::atomic::Ordering::AcqRel) { return Err(vfs::VfsError::Eio); }
    let size = entry_size(fmt)?;
    let mut rec = alloc::vec![0u8; size];
    mem_to_disk(id, dq, &mut rec);
    write_file_bytes(m, ino, inode, off, &rec)
}
