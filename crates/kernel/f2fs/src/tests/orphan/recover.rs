//! Reclaiming at mount what a crash left parked.
//!
//! The pack is built here by hand rather than by the writer under test, so a
//! passing test proves the reader agrees with the FORMAT, not with our own
//! encoder. The patcher below lays orphan blocks between the payload and the
//! summaries exactly as a checkpoint must: it moves the summaries out, writes
//! the blocks into the gap, and rewrites the head and tail with both pack
//! numbers advanced. Each of those three steps can be switched off, because
//! each of them is a defect somebody will reintroduce.

use alloc::vec::Vec;

use sectors::MemImage;

use crate::checksum;
use crate::flags::CP_ORPHAN_PRESENT_FLAG;
use crate::opts::Options;
use crate::summary::normal_sum_addr;
use crate::test_image::ROOT_INO;
use crate::uapi::{
    le32, BLKSIZE, CP_CKPT_FLAGS, CP_PACKS, CP_PACK_START_SUM, CP_PACK_TOTAL_BLOCK_COUNT,
    NR_CURSEG_PERSIST_TYPE,
};
use crate::volume::orphan::block::{self, AT_ENTRY_COUNT, ORPHANS_PER_BLOCK};
use crate::volume::Volume;

use super::live;

use syscall::errno::Errno;

/// Which parts of a correct pack the fixture actually writes.
pub struct Patch {
    /// Push `cp_pack_start_sum` past the orphan blocks.
    pub advance_start_sum: bool,
    /// Push `cp_pack_total_block_count` past them, moving the summaries and
    /// the tail out of their way.
    pub advance_total: bool,
    pub set_flag: bool,
    /// Overwrite the first block's entry count with something a writer would
    /// never produce.
    pub entry_count: Option<u32>,
    /// Overwrite `cp_pack_start_sum` outright.
    pub start_sum: Option<u32>,
    /// One inode per block instead of a packed array, to prove the reader
    /// walks the whole region rather than only its first block.
    pub split: bool,
}

impl Patch {
    /// A pack written the way a checkpoint must write it. # C: O(1)
    pub fn sane() -> Self {
        Self {
            advance_start_sum: true,
            advance_total: true,
            set_flag: true,
            entry_count: None,
            start_sum: None,
            split: false,
        }
    }
}

fn get(bytes: &[u8], addr: u32) -> Vec<u8> {
    let at = addr as usize * BLKSIZE;
    bytes[at..at + BLKSIZE].to_vec()
}

fn put(bytes: &mut [u8], addr: u32, block: &[u8]) {
    let at = addr as usize * BLKSIZE;
    bytes[at..at + BLKSIZE].copy_from_slice(block);
}

fn p32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }

/// Rewrite the pack at `start` so it carries `inos` as its orphan list.
/// # C: O(pack blocks)
fn park_in_pack(bytes: &mut [u8], start: u32, payload: u32, inos: &[u32], p: &Patch) {
    let mut head = get(bytes, start);
    let old_total = le32(&head, CP_PACK_TOTAL_BLOCK_COUNT).unwrap();
    // How many summaries this pack keeps is the writer's choice and depends on
    // why it was written, so it is read back off the pack rather than assumed.
    let logs = (old_total - CP_PACKS - payload) as usize;
    assert!((1..=NR_CURSEG_PERSIST_TYPE).contains(&logs), "unexpected pack shape: {old_total}");
    assert_eq!(block::pack_total(payload, 0, logs), old_total, "fixture geometry moved");
    let blocks: Vec<Vec<u8>> = if p.split {
        let n = inos.len() as u16;
        inos.iter().enumerate().map(|(i, x)| block::encode(&[*x], i as u16 + 1, n).unwrap()).collect()
    } else {
        block::encode_all(inos)
    };
    let ob = blocks.len() as u32;
    let total = if p.advance_total { block::pack_total(payload, ob, logs) } else { old_total };
    // Descending, because the summaries move to HIGHER addresses and an
    // ascending copy would overwrite the ones not yet moved.
    for log in (0..logs).rev() {
        let from = normal_sum_addr(start, old_total, logs, log);
        let to = normal_sum_addr(start, total, logs, log);
        if from != to { let b = get(bytes, from); put(bytes, to, &b); }
    }
    for (i, b) in blocks.iter().enumerate() {
        let mut b = b.clone();
        if i == 0 {
            if let Some(n) = p.entry_count { p32(&mut b, AT_ENTRY_COUNT, n); }
        }
        put(bytes, start + 1 + payload + i as u32, &b);
    }
    let start_sum = p.start_sum.unwrap_or(if p.advance_start_sum {
        block::pack_start_sum(payload, ob)
    } else {
        block::pack_start_sum(payload, 0)
    });
    p32(&mut head, CP_PACK_START_SUM, start_sum);
    p32(&mut head, CP_PACK_TOTAL_BLOCK_COUNT, total);
    let flags = le32(&head, CP_CKPT_FLAGS).unwrap();
    let flags = if p.set_flag { flags | CP_ORPHAN_PRESENT_FLAG } else { flags & !CP_ORPHAN_PRESENT_FLAG };
    p32(&mut head, CP_CKPT_FLAGS, flags);
    let off = checksum::crc_offset(&head).unwrap();
    let crc = checksum::crc32(&head[..off]);
    p32(&mut head, off, crc);
    put(bytes, start, &head);
    put(bytes, start + total - 1, &head);
}

/// What a crash between an unlink and the last close leaves on the medium.
pub struct Parked {
    pub bytes: Vec<u8>,
    pub inos: Vec<u32>,
    pub addrs: Vec<u32>,
    pub payload: u32,
    /// First block of the pack the list was written into.
    pub start: u32,
}

impl Parked {
    /// The pack's first orphan block, as it sits on the medium. # C: O(BLKSIZE)
    pub fn orphan_block(&self) -> Vec<u8> { get(&self.bytes, self.start + 1 + self.payload) }
}

/// Build a volume whose `names` have gone but whose inodes have not, and park
/// those inodes in its current pack. # C: O(image bytes)
fn parked(names: &[&[u8]], p: &Patch) -> Parked {
    let mut v = live::vol();
    let mut inos = Vec::new();
    let mut addrs = Vec::new();
    for name in names {
        let ino = live::file_with_a_block(&mut v, name);
        addrs.push(live::data_addr(&v, ino));
        inos.push(ino);
    }
    for name in names { v.remove_dentry(ROOT_INO, name).unwrap(); }
    v.commit().unwrap();
    let (start, payload) = {
        let sb = v.super_block();
        (v.checkpoint().start(sb.cp_blkaddr, sb.blks_per_seg()), sb.cp_payload)
    };
    let mut bytes = v.into_source().snapshot();
    park_in_pack(&mut bytes, start, payload, &inos, p);
    Parked { bytes, inos, addrs, payload, start }
}

fn open(bytes: Vec<u8>, write: bool) -> Result<Volume<MemImage>, Errno> {
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), write)
}

fn mount(bytes: Vec<u8>, write: bool) -> Volume<MemImage> { open(bytes, write).unwrap() }

/// Mount and recover, whichever of the two does the reading.
///
/// A mount that recovers on the way in reports a refused pack as a failed
/// mount; one that leaves it to the caller reports it from the call. Both are
/// the same refusal, and a test that only knew one of them would go red the
/// day the other is wired.
/// # C: O(image bytes)
fn mount_and_recover(bytes: Vec<u8>) -> Result<Volume<MemImage>, Errno> {
    let mut v = open(bytes, true)?;
    v.recover_orphans()?;
    Ok(v)
}

// --------------------------------------------------------------- recovery

#[test]
fn a_pack_that_parked_an_inode_still_holds_it_before_anything_reclaims() {
    // A mount that cannot write leaves the list alone: the blocks stay
    // counted, which a later mount can still repair, where a half-done
    // reclaim on a medium that cannot record it cannot be.
    let park = parked(&[b"held"], &Patch::sane());
    let (ino, addr) = (park.inos[0], park.addrs[0]);
    let v = mount(park.bytes, false);
    assert!(v.checkpoint().has(CP_ORPHAN_PRESENT_FLAG));
    assert_eq!(
        block::blocks_in_pack(v.checkpoint().pack_start_sum, park.payload),
        Some(1),
        "the gap between the payload and the summaries names one orphan block"
    );
    assert!(v.read_inode(ino).is_ok(), "the inode is real, just unreachable");
    assert!(v.block_is_live(addr).unwrap());
}

#[test]
fn recovery_frees_what_the_pack_parked() {
    // A writable mount reclaims on the way in, before anything can allocate:
    // a node id still owned by an unreclaimed orphan handed to a new file
    // would give two inodes one number.
    let park = parked(&[b"held"], &Patch::sane());
    let (ino, addr) = (park.inos[0], park.addrs[0]);
    let v = mount(park.bytes, true);
    assert!(v.read_inode(ino).is_err(), "the parked inode must be gone");
    assert!(!v.block_is_live(addr).unwrap(), "its block must come back");
    assert!(!v.checkpoint().has(CP_ORPHAN_PRESENT_FLAG));
    assert!(v.is_dirty(), "the cleared flag has to reach a checkpoint");
}

#[test]
fn recovery_frees_every_inode_in_the_list() {
    let park = parked(&[b"a", b"b", b"c"], &Patch::sane());
    let v = mount(park.bytes, true);
    for (i, ino) in park.inos.iter().enumerate() {
        assert!(v.read_inode(*ino).is_err(), "inode {ino} survived");
        assert!(!v.block_is_live(park.addrs[i]).unwrap(), "block {i} still live");
    }
    assert!(v.orphan_list().is_empty());
}

#[test]
fn recovery_walks_every_block_of_the_region_not_only_the_first() {
    let mut p = Patch::sane();
    p.split = true;
    let park = parked(&[b"a", b"b", b"c"], &p);
    let mut v = mount(park.bytes, true);
    assert_eq!(block::blocks_in_pack(v.checkpoint().pack_start_sum, park.payload), Some(3));
    v.recover_orphans().unwrap();
    for ino in &park.inos { assert!(v.read_inode(*ino).is_err(), "inode {ino} survived"); }
}

#[test]
fn a_reclaimed_inodes_blocks_come_back_to_the_volume() {
    let park = parked(&[b"held"], &Patch::sane());
    // Read-only first, because a mount that recovers on the way in has already
    // given the blocks back by the time it hands the volume over.
    let before = mount(park.bytes.clone(), false).space().free;
    let mut v = mount(park.bytes, true);
    v.recover_orphans().unwrap();
    v.commit().unwrap();
    let after = v.space().free;
    // The inode's own node block and its one data block.
    assert_eq!(after, before + 2, "free space must reflect the reclaim");
}

#[test]
fn the_pack_shrinks_back_once_nothing_is_parked() {
    let park = parked(&[b"held"], &Patch::sane());
    let payload = park.payload;
    let mut v = mount(park.bytes, true);
    v.recover_orphans().unwrap();
    v.commit().unwrap();
    let v = mount(v.into_source().snapshot(), true);
    let cp = v.checkpoint();
    assert!(!cp.has(CP_ORPHAN_PRESENT_FLAG), "the flag must not survive the reclaim");
    assert_eq!(cp.pack_start_sum, block::pack_start_sum(payload, 0));
    assert_eq!(block::blocks_in_pack(cp.pack_start_sum, payload), Some(0));
    // Whatever the pack chose to keep, the tail must sit one past its last
    // summary and nothing may be left in the gap.
    let logs = (cp.pack_total_block_count - CP_PACKS - payload) as usize;
    assert_eq!(cp.pack_total_block_count, block::pack_total(payload, 0, logs));
    assert!(logs >= 1 && logs <= NR_CURSEG_PERSIST_TYPE, "unexpected pack shape");
    assert!(v.orphan_list().is_empty());
}

// --------------------------------------------------------------- refusals

#[test]
fn recovery_is_skipped_when_the_flag_is_clear() {
    let mut p = Patch::sane();
    p.set_flag = false;
    let park = parked(&[b"held"], &p);
    let (ino, addr) = (park.inos[0], park.addrs[0]);
    let mut v = mount(park.bytes, true);
    v.recover_orphans().unwrap();
    assert!(v.read_inode(ino).is_ok(), "nothing said the blocks were there");
    assert!(v.block_is_live(addr).unwrap());
}

#[test]
fn a_read_only_mount_reclaims_nothing() {
    let park = parked(&[b"held"], &Patch::sane());
    let (ino, addr) = (park.inos[0], park.addrs[0]);
    let mut v = mount(park.bytes, false);
    assert!(!v.writable());
    v.recover_orphans().unwrap();
    assert!(v.read_inode(ino).is_ok(), "a mount that cannot record a reclaim must not do one");
    assert!(v.block_is_live(addr).unwrap());
    assert!(v.checkpoint().has(CP_ORPHAN_PRESENT_FLAG), "the list is still owed");
}

#[test]
fn recovery_reads_exactly_the_gap_the_pack_numbers_name() {
    let mut p = Patch::sane();
    p.advance_start_sum = false;
    let park = parked(&[b"held"], &p);
    let ino = park.inos[0];
    let mut v = mount(park.bytes, true);
    assert_eq!(block::blocks_in_pack(v.checkpoint().pack_start_sum, park.payload), Some(0));
    v.recover_orphans().unwrap();
    // A pack whose summaries start where they always did says it holds no
    // orphan blocks, whatever was written into the gap.
    assert!(v.read_inode(ino).is_ok());
}

#[test]
fn recovery_refuses_an_entry_count_the_block_cannot_hold() {
    let mut p = Patch::sane();
    p.entry_count = Some(ORPHANS_PER_BLOCK as u32 + 1);
    let park = parked(&[b"a", b"b", b"c"], &p);
    // The refusal has to come from the BLOCK, not from choking part-way down
    // an over-long list. Recovery reports the same errno either way — it reads
    // every inode number before freeing any, and the entries past the real
    // ones are zero padding that fails to resolve — so the errno alone cannot
    // tell a bounded read from an unbounded one. The block itself can.
    assert!(
        block::decode(&park.orphan_block()).is_none(),
        "a block claiming more entries than it holds must be refused whole"
    );
    assert_eq!(mount_and_recover(park.bytes.clone()).err(), Some(Errno::Einval));
    let v = mount(park.bytes, false);
    for (i, ino) in park.inos.iter().enumerate() {
        assert!(v.read_inode(*ino).is_ok(), "nothing may be freed off a refused block");
        assert!(v.block_is_live(park.addrs[i]).unwrap());
    }
}

#[test]
fn recovery_refuses_an_absurd_entry_count() {
    for bogus in [u32::MAX, 0x4000_0000] {
        let mut p = Patch::sane();
        p.entry_count = Some(bogus);
        let park = parked(&[b"held"], &p);
        assert_eq!(mount_and_recover(park.bytes).err(), Some(Errno::Einval), "{bogus} accepted");
    }
}

#[test]
fn recovery_refuses_summaries_that_start_before_the_payload_ends() {
    let mut p = Patch::sane();
    p.start_sum = Some(0);
    let park = parked(&[b"held"], &p);
    assert_eq!(mount_and_recover(park.bytes).err(), Some(Errno::Einval));
}

// --------------------------------------------------- the writer's own pack

#[test]
fn an_open_inode_survives_a_checkpoint_and_is_reclaimed_at_the_next_mount() {
    let mut v = live::vol();
    let ino = live::file_with_a_block(&mut v, b"held");
    let addr = live::data_addr(&v, ino);
    v.open_inode(ino);
    let gone = v.remove_dentry(ROOT_INO, b"held").unwrap();
    assert_eq!(gone, ino);
    v.drop_last_link(ino, live::NOW).unwrap();
    v.commit().unwrap();
    let (start, payload) = {
        let sb = v.super_block();
        (v.checkpoint().start(sb.cp_blkaddr, sb.blks_per_seg()), sb.cp_payload)
    };
    let bytes = v.into_source().snapshot();
    // Read the flag off the pack itself: a mount that recovers on the way in
    // clears it in memory, so the mounted view cannot answer what was WRITTEN.
    let head = get(&bytes, start);
    assert_ne!(
        le32(&head, CP_CKPT_FLAGS).unwrap() & CP_ORPHAN_PRESENT_FLAG,
        0,
        "the pack must say its orphan blocks are there"
    );
    let mut v = mount(bytes, true);
    // The checkpoint the writer produced must describe the list the reader
    // then finds: one block in the gap before the summaries.
    assert_eq!(block::blocks_in_pack(v.checkpoint().pack_start_sum, payload), Some(1));
    v.recover_orphans().unwrap();
    assert!(v.read_inode(ino).is_err(), "the orphan outlived its checkpoint");
    assert!(!v.block_is_live(addr).unwrap());
}

#[test]
fn a_checkpoint_with_nothing_parked_carries_no_orphan_blocks() {
    let mut v = live::vol();
    live::file_with_a_block(&mut v, b"kept");
    v.commit().unwrap();
    let payload = v.super_block().cp_payload;
    let v = mount(v.into_source().snapshot(), true);
    let cp = v.checkpoint();
    assert!(!cp.has(CP_ORPHAN_PRESENT_FLAG));
    assert_eq!(cp.pack_start_sum, block::pack_start_sum(payload, 0));
    assert_eq!(block::blocks_in_pack(cp.pack_start_sum, payload), Some(0));
    let logs = (cp.pack_total_block_count - CP_PACKS - payload) as usize;
    assert_eq!(cp.pack_total_block_count, block::pack_total(payload, 0, logs));
}

#[test]
fn an_unlink_of_an_open_file_parks_it_and_a_close_reclaims_it_across_a_mount() {
    let mut v = live::vol();
    let ino = live::file_with_a_block(&mut v, b"held");
    let addr = live::data_addr(&v, ino);
    v.open_inode(ino);
    v.remove(ROOT_INO, b"held", false, live::NOW).unwrap();
    assert!(v.is_orphan(ino), "remove must park an inode something holds open");
    v.commit().unwrap();
    let mut v = mount(v.into_source().snapshot(), true);
    v.recover_orphans().unwrap();
    assert!(v.read_inode(ino).is_err());
    assert!(!v.block_is_live(addr).unwrap());
}
