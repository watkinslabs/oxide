use crate::inode::Inode;
use crate::mount::Mount;

use super::backend::{QBLK_BITS, QBLK_SIZE, QT_DQDBHEADER, QT_TREEOFF, Qinfo, entries_per_blk, le16, le32, put16, put32, qindex, read_qblk, write_qblk};

/// Delete a quota record from the Linux VFS-v1 qtree. # C: O(qtree depth)
pub(super) fn delete_dquot(
    m: &Mount,
    ino: u32,
    inode: &Inode,
    qi: &mut Qinfo,
    qid: vfs::Kqid,
    off: u64,
) -> vfs::KResult<()> {
    if !delete_tree_needed(off, qi.depth)? { return Ok(()); }
    let mut blks = [0u32; super::backend::MAX_QTREE_DEPTH];
    blks[0] = QT_TREEOFF;
    remove_tree(m, ino, inode, qi, qid.id, off, &mut blks, 0)
}

fn delete_tree_needed(off: u64, depth: usize) -> vfs::KResult<bool> {
    if off == 0 { return Ok(false); }
    if depth >= super::backend::MAX_QTREE_DEPTH { return Err(vfs::VfsError::Eio); }
    Ok(true)
}

fn remove_tree(
    m: &Mount,
    ino: u32,
    inode: &Inode,
    qi: &mut Qinfo,
    id: u32,
    off: u64,
    blks: &mut [u32; super::backend::MAX_QTREE_DEPTH],
    depth: usize,
) -> vfs::KResult<()> {
    let mut buf = read_qblk(m, inode, blks[depth])?;
    let idx = qindex(id, depth);
    let next = le32(&buf, idx * 4);
    if next < QT_TREEOFF || next >= qi.blocks { return Err(vfs::VfsError::Eio); }
    for used in blks.iter().take(depth + 1) {
        if *used == next { return Err(vfs::VfsError::Eio); }
    }
    blks[depth + 1] = next;
    if depth + 1 == qi.depth {
        free_dqentry(m, ino, inode, qi, off, next)?;
        blks[depth + 1] = 0;
    } else {
        remove_tree(m, ino, inode, qi, id, off, blks, depth + 1)?;
    }
    if blks[depth + 1] == 0 {
        put32(&mut buf, idx * 4, 0);
        if blks[depth] != QT_TREEOFF && tree_block_empty(&buf) {
            put_free_qblk(m, ino, inode, qi, blks[depth], &mut buf)?;
            blks[depth] = 0;
        } else {
            write_qblk(m, ino, inode, blks[depth], &buf)?;
        }
    }
    Ok(())
}

fn free_dqentry(m: &Mount, ino: u32, inode: &Inode, qi: &mut Qinfo, off: u64, blk: u32) -> vfs::KResult<()> {
    if (off >> QBLK_BITS) as u32 != blk { return Err(vfs::VfsError::Eio); }
    let mut buf = read_qblk(m, inode, blk)?;
    check_dqdb_header(qi, &buf)?;
    let entries = le16(&buf, 8);
    if entries == 0 { return Err(vfs::VfsError::Eio); }
    put16(&mut buf, 8, entries - 1);
    if entries == 1 {
        remove_free_dqentry(m, ino, inode, qi, blk, &mut buf)?;
        put_free_qblk(m, ino, inode, qi, blk, &mut buf)
    } else {
        let inner = (off & ((1u64 << QBLK_BITS) - 1)) as usize;
        if inner < QT_DQDBHEADER || inner + qi.entry_size > QBLK_SIZE { return Err(vfs::VfsError::Eio); }
        buf[inner..inner + qi.entry_size].fill(0);
        if entries as usize == entries_per_blk(qi) {
            insert_free_dqentry(m, ino, inode, qi, blk, &mut buf)
        } else {
            write_qblk(m, ino, inode, blk, &buf)
        }
    }
}

fn insert_free_dqentry(m: &Mount, ino: u32, inode: &Inode, qi: &mut Qinfo, blk: u32, buf: &mut [u8]) -> vfs::KResult<()> {
    put32(buf, 0, qi.free_entry);
    put32(buf, 4, 0);
    write_qblk(m, ino, inode, blk, buf)?;
    if qi.free_entry != 0 {
        let mut head = read_qblk(m, inode, qi.free_entry)?;
        put32(&mut head, 4, blk);
        write_qblk(m, ino, inode, qi.free_entry, &head)?;
    }
    qi.free_entry = blk;
    Ok(())
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

fn put_free_qblk(m: &Mount, ino: u32, inode: &Inode, qi: &mut Qinfo, blk: u32, buf: &mut [u8]) -> vfs::KResult<()> {
    buf.fill(0);
    put32(buf, 0, qi.free_blk);
    put32(buf, 4, 0);
    put16(buf, 8, 0);
    write_qblk(m, ino, inode, blk, buf)?;
    qi.free_blk = blk;
    Ok(())
}

fn check_dqdb_header(qi: &Qinfo, buf: &[u8]) -> vfs::KResult<()> {
    if le32(buf, 0) >= qi.blocks { return Err(vfs::VfsError::Eio); }
    if le32(buf, 4) >= qi.blocks { return Err(vfs::VfsError::Eio); }
    if le16(buf, 8) as usize > entries_per_blk(qi) { return Err(vfs::VfsError::Eio); }
    Ok(())
}

fn tree_block_empty(buf: &[u8]) -> bool {
    for i in 0..QBLK_SIZE / 4 {
        if le32(buf, i * 4) != 0 { return false; }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_start_matches_linux_depth_error() {
        assert_eq!(delete_tree_needed(0, super::super::backend::MAX_QTREE_DEPTH), Ok(false));
        assert_eq!(delete_tree_needed(1, super::super::backend::MAX_QTREE_DEPTH), Err(vfs::VfsError::Eio));
        assert_eq!(delete_tree_needed(1, super::super::backend::MAX_QTREE_DEPTH - 1), Ok(true));
    }
}
