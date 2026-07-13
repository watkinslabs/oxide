use alloc::vec::Vec;

use crate::inode::Inode;
use crate::mount::Mount;

use super::backend::{
    QBLK_BITS, QBLK_SIZE, QT_DQDBHEADER, QT_TREEOFF, Qinfo, entry_unused, le16,
    le32, qindex, read_qblk,
};
use super::format::disk_to_mem;

/// Read one quota record from the Linux VFS qtree. # C: O(qtree depth)
pub(super) fn read_dquot_at(m: &Mount, inode: &Inode, qi: &Qinfo, qid: vfs::Kqid) -> vfs::KResult<Option<(u64, vfs::MemDqblk)>> {
    let mut blk = QT_TREEOFF;
    for depth in 0..qi.depth {
        let buf = read_qblk(m, inode, blk)?;
        let next = le32(&buf, qindex(qid.id, depth) * 4);
        if next == 0 { return Ok(None); }
        if next <= QT_TREEOFF || next >= qi.blocks { return Err(vfs::VfsError::Eio); }
        if depth + 1 == qi.depth {
            return find_in_leaf(m, inode, qi, next, qid.id);
        }
        blk = next;
    }
    Ok(None)
}

/// Read the next quota id by walking qtree references like Linux `find_next_id`. # C: O(quota-file)
pub(super) fn next_tree_id(m: &Mount, inode: &Inode, qi: &Qinfo, kind: vfs::QuotaType, start: u32) -> vfs::KResult<Option<vfs::Kqid>> {
    let mut id = start;
    match find_next_id(m, inode, qi, QT_TREEOFF, 0, &mut id)? {
        true => Ok(Some(vfs::Kqid { kind, id })),
        false => Ok(None),
    }
}

fn find_next_id(m: &Mount, inode: &Inode, qi: &Qinfo, blk: u32, depth: usize, id: &mut u32) -> vfs::KResult<bool> {
    if depth >= qi.depth || blk >= qi.blocks { return Err(vfs::VfsError::Eio); }
    let buf = read_qblk(m, inode, blk)?;
    find_next_id_refs(qi, depth, id, |idx| Ok(le32(&buf, idx * 4)), |next, depth, id| {
        if depth + 1 == qi.depth { return find_next_leaf_id(m, inode, qi, next, *id, id); }
        find_next_id(m, inode, qi, next, depth + 1, id)
    })
}

fn find_next_id_refs<Ref, Descend>(qi: &Qinfo, depth: usize, id: &mut u32, mut ref_at: Ref, mut descend: Descend) -> vfs::KResult<bool>
where
    Ref: FnMut(usize) -> vfs::KResult<u32>,
    Descend: FnMut(u32, usize, &mut u32) -> vfs::KResult<bool>,
{
    let epb = QBLK_SIZE / 4;
    let inc = level_inc(qi, depth);
    for i in qindex(*id, depth)..epb {
        let next = ref_at(i)?;
        if next == 0 {
            *id = id.wrapping_add(inc);
            continue;
        }
        if next <= QT_TREEOFF || next >= qi.blocks { return Err(vfs::VfsError::Eio); }
        if descend(next, depth, id)? { return Ok(true); }
    }
    Ok(false)
}

fn find_next_leaf_id(m: &Mount, inode: &Inode, qi: &Qinfo, blk: u32, start: u32, id: &mut u32) -> vfs::KResult<bool> {
    let buf = read_qblk(m, inode, blk)?;
    let entries = (QBLK_SIZE - QT_DQDBHEADER) / qi.entry_size;
    if le16(&buf, 8) as usize > entries { return Err(vfs::VfsError::Eio); }
    let mut best = None;
    for n in 0..entries {
        let off = QT_DQDBHEADER + n * qi.entry_size;
        let rec = &buf[off..off + qi.entry_size];
        if entry_unused(rec) { continue; }
        let rec_id = le32(rec, 0);
        if rec_id < start { continue; }
        best = Some(best.map_or(rec_id, |old: u32| old.min(rec_id)));
    }
    if let Some(found) = best {
        *id = found;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn find_in_leaf(m: &Mount, inode: &Inode, qi: &Qinfo, blk: u32, id: u32) -> vfs::KResult<Option<(u64, vfs::MemDqblk)>> {
    let buf = read_qblk(m, inode, blk)?;
    let entries = ((QBLK_SIZE - QT_DQDBHEADER) / qi.entry_size) as u16;
    if le16(&buf, 8) > entries { return Err(vfs::VfsError::Eio); }
    for n in 0..entries as usize {
        let off = QT_DQDBHEADER + n * qi.entry_size;
        if entry_unused(&buf[off..off + qi.entry_size]) { continue; }
        if le32(&buf, off) == id {
            return Ok(Some((((blk as u64) << QBLK_BITS) + off as u64, disk_to_mem(&buf[off..off + qi.entry_size]))));
        }
    }
    Ok(None)
}

/// Collect every active quota record from the persistent qtree. # C: O(quota-file)
pub(super) fn collect_tree(m: &Mount, inode: &Inode, qi: &Qinfo, kind: vfs::QuotaType, blk: u32, depth: usize, base: u32, out: &mut Vec<(vfs::Kqid, u64, vfs::MemDqblk)>)
    -> vfs::KResult<()>
{
    if depth >= super::backend::MAX_QTREE_DEPTH || blk >= qi.blocks { return Err(vfs::VfsError::Eio); }
    let buf = read_qblk(m, inode, blk)?;
    let epb = QBLK_SIZE / 4;
    for i in 0..epb {
        let next = le32(&buf, i * 4);
        if next == 0 { continue; }
        if next <= QT_TREEOFF || next >= qi.blocks { return Err(vfs::VfsError::Eio); }
        let id_base = base.wrapping_add((i as u32).wrapping_mul(level_inc(qi, depth)));
        if depth + 1 == qi.depth {
            collect_leaf(m, inode, kind, qi, next, id_base, out)?;
        } else {
            collect_tree(m, inode, qi, kind, next, depth + 1, id_base, out)?;
        }
    }
    Ok(())
}

fn collect_leaf(m: &Mount, inode: &Inode, kind: vfs::QuotaType, qi: &Qinfo, blk: u32, _base: u32, out: &mut Vec<(vfs::Kqid, u64, vfs::MemDqblk)>) -> vfs::KResult<()> {
    let buf = read_qblk(m, inode, blk)?;
    let entries = (QBLK_SIZE - QT_DQDBHEADER) / qi.entry_size;
    if le16(&buf, 8) as usize > entries { return Err(vfs::VfsError::Eio); }
    for n in 0..entries {
        let off = QT_DQDBHEADER + n * qi.entry_size;
        let rec = &buf[off..off + qi.entry_size];
        if entry_unused(rec) { continue; }
        let id = le32(rec, 0);
        out.push((vfs::Kqid { kind, id }, ((blk as u64) << QBLK_BITS) + off as u64, disk_to_mem(rec)));
    }
    Ok(())
}

fn level_inc(qi: &Qinfo, depth: usize) -> u32 {
    let mut n = 1u32;
    for _ in depth..qi.depth - 1 { n = n.wrapping_mul(256); }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qi() -> Qinfo { Qinfo { blocks: 64, free_blk: 0, free_entry: 0, depth: 4, entry_size: 72 } }

    #[test]
    fn find_next_id_refs_returns_path_id_not_stored_record_id() {
        let qi = qi();
        let mut id = 1u32;
        let mut root = [0u32; QBLK_SIZE / 4];
        root[0] = 2;

        let found = find_next_id_refs(&qi, 0, &mut id, |idx| Ok(root[idx]), |_next, depth, _id| {
            assert_eq!(depth, 0);
            Ok(true)
        }).unwrap();

        assert!(found);
        assert_eq!(id, 1);
    }

    #[test]
    fn find_next_id_refs_skips_empty_ranges_like_linux() {
        let qi = qi();
        let mut id = 1u32;
        let root = [0u32; QBLK_SIZE / 4];

        let found = find_next_id_refs(&qi, 1, &mut id, |idx| Ok(root[idx]), |_next, _depth, _id| Ok(true)).unwrap();

        assert!(!found);
        assert_eq!(id, 1 + 256 * 256 * 256);
    }
}
