// Lazy inode-table initialisation driven against a real image: a group whose
// descriptor says its table was never written out gets zeroed, gets flagged,
// and is not zeroed twice.

use alloc::sync::Arc;
use alloc::vec::Vec;
use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

use crate::gdt;
use crate::rootfs::Ext4Mount;

const IMAGE: &[u8] = include_bytes!("../../tests/mini-j.img");
const SECTOR: u32 = 512;
/// The group every ext4 image has.
const FIRST_GROUP: u32 = 0;
/// A byte no zeroed inode table may still contain.
const GARBAGE: u8 = 0xA5;

fn fresh_dev() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let inner: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: Vec::from(IMAGE), ..Default::default()
    };
    inner.submit_sync(&mut req).unwrap();
    inner
}

fn mount(data: &str) -> Arc<crate::Mount> {
    Ext4Mount::open_with_data(fresh_dev(), None, data).expect("mounts").state().mount.clone()
}

/// Make group `n` look the way mkfs leaves a lazily-initialised group — not
/// yet zeroed, with the back half of its inodes never used — and scribble over
/// that never-used tail so there is something for the initialiser to remove.
/// Answers where the tail is and how long it is.
pub(crate) fn dirty_the_table(m: &Arc<crate::Mount>, n: u32) -> (u64, usize) {
    let (tail_off, tail_len) = {
        let mut s = m.state.lock();
        let dsize = gdt::desc_size_for(&m.sb) as usize;
        let base = (n as usize) * dsize;
        let foff = base + gdt::GD_OFF_FLAGS;
        let flags = u16::from_le_bytes([s.gdt_buf[foff], s.gdt_buf[foff + 1]])
            & !(gdt::EXT4_BG_INODE_ZEROED | gdt::EXT4_BG_INODE_UNINIT);
        s.gdt_buf[foff..foff + 2].copy_from_slice(&flags.to_le_bytes());
        let half = m.sb.inodes_per_group / 2;
        let uoff = base + gdt::GD_OFF_ITABLE_UNUSED_LO;
        s.gdt_buf[uoff..uoff + 2].copy_from_slice(&(half as u16).to_le_bytes());
        crate::csum::stamp_group_desc_csum(&m.sb, &mut s.gdt_buf, n);

        let d = gdt::parse_descriptor(&s.gdt_buf, n, &m.sb).unwrap();
        let geom = super::decide::TableGeometry::new(m.sb.inodes_per_group, m.sb.block_size,
                                                     m.sb.inode_size);
        let used = super::decide::used_itable_blocks(&geom, half, false).unwrap();
        let bs = m.sb.block_size as u64;
        ((d.inode_table + used as u64) * bs,
         ((geom.blocks_per_table - used) as u64 * bs) as usize)
    };
    assert!(tail_len != 0, "the image left no never-used inodes to zero");
    crate::mount::io_write_byte_range(&*m.dev, tail_off, &alloc::vec![GARBAGE; tail_len]).unwrap();
    (tail_off, tail_len)
}

fn read_back(m: &Arc<crate::Mount>, off: u64, len: usize) -> Vec<u8> {
    crate::mount::read_byte_range_pub(&*m.dev, off, len).unwrap()
}

/// The initialiser removes what was in the never-used part of the table, and
/// records that it did so where a later mount (and a filesystem check) reads it.
#[test]
fn an_uninitialised_table_is_zeroed_and_flagged() {
    let m = mount("");
    let (off, len) = dirty_the_table(&m, FIRST_GROUP);
    assert!(read_back(&m, off, len).iter().any(|b| *b == GARBAGE),
        "the probe wrote nothing to remove");

    assert_eq!(m.init_inode_table(FIRST_GROUP), Ok(true));
    assert!(read_back(&m, off, len).iter().all(|b| *b == 0),
        "the never-used part of the table is zeroed");
    assert!(gdt::inode_zeroed(&m.state.lock().gdt_buf, FIRST_GROUP, &m.sb),
        "and the group says so");
}

/// A group already flagged is not rewritten. Without this the job would zero
/// every table on every tick forever.
#[test]
fn an_already_initialised_table_is_left_alone() {
    let m = mount("");
    let (off, len) = dirty_the_table(&m, FIRST_GROUP);
    assert_eq!(m.init_inode_table(FIRST_GROUP), Ok(true));

    crate::mount::io_write_byte_range(&*m.dev, off, &alloc::vec![GARBAGE; len]).unwrap();
    assert_eq!(m.init_inode_table(FIRST_GROUP), Ok(false));
    assert!(read_back(&m, off, len).iter().any(|b| *b == GARBAGE),
        "a flagged group is not written again");
}

/// The walk answers which group it did, and answers nothing once every group
/// is done — which is what lets the timer stop looking at this mount.
#[test]
fn the_walk_reports_the_group_it_did_and_then_stops() {
    let m = mount("");
    dirty_the_table(&m, FIRST_GROUP);
    assert_eq!(m.init_next_inode_table(FIRST_GROUP), Ok(Some(FIRST_GROUP)));
    assert_eq!(m.init_next_inode_table(FIRST_GROUP), Ok(None));
}

/// A descriptor whose unused-inode count cannot be true of its group is
/// refused: zeroing on that count would destroy live inodes.
#[test]
fn an_impossible_unused_count_refuses_rather_than_zeroing() {
    let m = mount("");
    dirty_the_table(&m, FIRST_GROUP);
    {
        let mut s = m.state.lock();
        let dsize = gdt::desc_size_for(&m.sb) as usize;
        let off = (FIRST_GROUP as usize) * dsize;
        // Clear INODE_UNINIT so the unused count is the thing consulted, then
        // make it larger than the group can hold.
        let foff = off + gdt::GD_OFF_FLAGS;
        let flags = u16::from_le_bytes([s.gdt_buf[foff], s.gdt_buf[foff + 1]])
            & !gdt::EXT4_BG_INODE_UNINIT;
        s.gdt_buf[foff..foff + 2].copy_from_slice(&flags.to_le_bytes());
        let uoff = off + gdt::GD_OFF_ITABLE_UNUSED_LO;
        s.gdt_buf[uoff..uoff + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        crate::csum::stamp_group_desc_csum(&m.sb, &mut s.gdt_buf, FIRST_GROUP);
    }
    assert_eq!(m.init_inode_table(FIRST_GROUP),
        Err(crate::MountError::Gdt(gdt::GdtError::BadItableUnused)));
}

/// `noinit_itable` turns the job off; the mount option is the only thing that
/// decides whether the timer ever asks.
#[test]
fn the_option_decides_whether_the_job_runs_at_all() {
    assert_eq!(mount("noinit_itable").behaviour().li_wait_mult, None);
    assert_eq!(mount("init_itable=20").behaviour().li_wait_mult, Some(20));
}
