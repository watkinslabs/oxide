//! Bringing a volume up: the superblock, the checkpoint, and the journals.
//!
//! Order is forced by the data. The superblock names where the checkpoint area
//! is; the checkpoint names where its own summary blocks are and how wide the
//! version bitmaps are; the summary blocks hold the journals that override
//! both tables. Nothing later can be read without everything earlier.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::checkpoint::{self, Checkpoint, Pack};
use crate::checksum;
use crate::features::{self, Access};
use crate::flags::CP_COMPACT_SUM_FLAG;
use crate::opts::Options;
use crate::sb::{self, SuperBlock};
use crate::summary::{self, at, NatJournal, SitJournal};
use crate::uapi::*;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Mount `source` under `opts`, writing only if `want_write` and the
    /// volume both allow it.
    ///
    /// A volume whose features permit only reads mounts READ-ONLY rather than
    /// failing: refusing would leave a user unable to read a filesystem that
    /// is perfectly readable, and the mount reports what it settled on.
    /// # C: O(checkpoint + journal bytes)
    pub fn mount_with(source: S, opts: Options, want_write: bool) -> Result<Self, Errno> {
        let sb = read_super(&source)?;
        let access = sb::sanity::access(&sb).map_err(|_| Errno::Einval)?;
        let writable = want_write && access == Access::ReadWrite && source.writable();
        let (cp, cp_raw) = read_checkpoint(&source, &sb)?;
        let payload = sb.cp_payload;
        let nat_bitmap = checkpoint::nat_bitmap(&cp, &cp_raw, payload)
            .ok_or(Errno::Einval)?
            .to_vec();
        let sit_bitmap = checkpoint::sit_bitmap(&cp, &cp_raw, payload)
            .ok_or(Errno::Einval)?
            .to_vec();
        let (nat_journal, sit_journal) = read_journals(&source, &sb, &cp)?;
        let inode_seed = checksum::inode_seed(&sb.uuid);
        Ok(Self {
            source,
            sb,
            cp,
            cp_raw,
            nat_bitmap,
            sit_bitmap,
            nat_journal,
            sit_journal,
            inode_seed,
            opts,
            access,
            writable,
        })
    }
}

/// Read whichever superblock copy validates, trying them in order.
///
/// A copy that fails does not fail the mount: that is the whole reason there
/// are two. Only a volume where NEITHER validates is refused, and the error
/// reported is the first copy's, because it is the one a checker will look at.
/// # C: O(2 blocks)
pub fn read_super<S: SectorSource>(source: &S) -> Result<SuperBlock, Errno> {
    let mut first_err = None;
    for block in 0..SUPER_COPIES {
        let mut buf = vec![0u8; BLKSIZE];
        if source.read_sectors(block, &mut buf).is_err() { continue; }
        let Some(raw) = buf.get(SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE) else { continue };
        let Some(parsed) = sb::parse(raw) else {
            first_err.get_or_insert(Errno::Einval);
            continue;
        };
        match sb::check(&parsed, raw) {
            Ok(()) => return Ok(parsed),
            Err(_) => { first_err.get_or_insert(Errno::Einval); }
        }
    }
    Err(first_err.unwrap_or(Errno::Einval))
}

/// Read both checkpoint packs and keep the newer valid one, with its payload.
/// # C: O(payload blocks)
pub fn read_checkpoint<S: SectorSource>(source: &S, sb: &SuperBlock)
    -> Result<(Checkpoint, Vec<u8>), Errno> {
    let blks = sb.blks_per_seg();
    let first = try_pack(source, sb.cp_blkaddr, blks, Pack::First);
    let second = try_pack(source, sb.cp_blkaddr + blks, blks, Pack::Second);
    let cp = checkpoint::choose(first, second).ok_or(Errno::Einval)?;
    let start = cp.start(sb.cp_blkaddr, blks);
    let head = read_one(source, start)?;
    let mut payload = Vec::new();
    for i in 1..=sb.cp_payload {
        payload.push(read_one(source, start + i)?);
    }
    let raw = checkpoint::joined(&head, &payload);
    Ok((cp, raw))
}

/// One pack, or `None` when it does not validate. # C: O(2 blocks)
fn try_pack<S: SectorSource>(source: &S, start: u32, blks_per_seg: u32, pack: Pack)
    -> Option<Checkpoint> {
    let head = read_one(source, start).ok()?;
    // The tail's position comes from the head, so the head's claim is bounded
    // before it is used as an address.
    let total = le32(&head, CP_PACK_TOTAL_BLOCK_COUNT)?;
    if total > blks_per_seg || total <= CP_PACKS { return None; }
    let tail = read_one(source, start + total - 1).ok()?;
    checkpoint::validate(&head, &tail, blks_per_seg, pack).ok()
}

/// One block, straight off the medium. # C: O(BLKSIZE)
fn read_one<S: SectorSource>(source: &S, addr: u32) -> Result<Vec<u8>, Errno> {
    let mut buf = vec![0u8; BLKSIZE];
    source.read_sectors(u64::from(addr), &mut buf)?;
    Ok(buf)
}

/// The two journals the current checkpoint parked in the summary area.
///
/// Which blocks hold them depends on two checkpoint flags: whether the
/// summaries were written compacted, and whether the node summaries were
/// written at all. Reading the wrong block yields a journal of plausible
/// nonsense whose entries then override correct table entries.
/// # C: O(2 blocks)
pub fn read_journals<S: SectorSource>(source: &S, sb: &SuperBlock, cp: &Checkpoint)
    -> Result<(NatJournal, SitJournal), Errno> {
    let start = cp.start(sb.cp_blkaddr, sb.blks_per_seg());
    if cp.has(CP_COMPACT_SUM_FLAG) {
        let block = read_one(source, start + cp.pack_start_sum)?;
        let nat = summary::nat_journal(&block, at::COMPACT_NAT).ok_or(Errno::Einval)?;
        let sit = summary::sit_journal(&block, at::COMPACT_SIT).ok_or(Errno::Einval)?;
        return Ok((nat, sit));
    }
    let base = if cp.node_summaries_present() { NR_CURSEG_PERSIST_TYPE } else { NR_CURSEG_DATA_TYPE };
    let total = cp.pack_total_block_count;
    let nat_blk = summary::normal_sum_addr(start, total, base, CURSEG_HOT_DATA);
    let sit_blk = summary::normal_sum_addr(start, total, base, CURSEG_COLD_DATA);
    let nat = summary::nat_journal(&read_one(source, nat_blk)?, at::NORMAL).ok_or(Errno::Einval)?;
    let sit = summary::sit_journal(&read_one(source, sit_blk)?, at::NORMAL).ok_or(Errno::Einval)?;
    if nat.len() > NAT_JOURNAL_ENTRIES || sit.len() > SIT_JOURNAL_ENTRIES {
        return Err(Errno::Einval);
    }
    Ok((nat, sit))
}

/// What a volume's features permit, without mounting it. # C: O(1)
pub fn probe_access(sb: &SuperBlock) -> Result<Access, features::Refusal> {
    features::access(sb.feature, sb.multi_device())
}
