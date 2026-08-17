//! The placement controls, read and written through the same `show` and `store`
//! a tool would run.
//!
//! An attribute that parses a number is not the property under test. What is
//! tested is that the number REACHES the decision that acts on it: every knob
//! here is written through the file and then observed changing an address a
//! rewrite lands on, or the input the recycling decision compares.

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::VfsError;

use crate::fsattr::Attr;
use crate::mount::F2fs;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::place::bits;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{Holder, NewInode};

const BS: u32 = BLKSIZE as u32;
const NOW: (u64, u32) = (1_800_000_000, 3);

fn mounted() -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    F2fs::open_with(dev, "/dev/vda", true, Options::defaults()).expect("mount")
}

fn attrs(fs: &Arc<F2fs>) -> alloc::vec::Vec<Attr> { super::attrs(fs, "vda") }

fn find<'a>(a: &'a [Attr], name: &str) -> &'a Attr {
    a.iter().find(|x| x.name == name).unwrap_or_else(|| panic!("no attribute {name}"))
}

fn show(a: &[Attr], name: &str) -> u64 {
    let bytes = (find(a, name).show)().expect("show");
    String::from_utf8(bytes).expect("utf-8").trim().parse().expect("number")
}

fn store(a: &[Attr], name: &str, v: u64) -> Result<usize, VfsError> {
    let text = alloc::format!("{v}\n");
    (find(a, name).store.as_ref().expect("writable"))(text.as_bytes())
}

/// One file with one placed block, and the address it landed on. The armed set
/// is cleared through the ATTRIBUTE first, so the address a later assertion
/// compares against is one an unarmed mount chose.
fn with_placed_block(fs: &Arc<F2fs>, a: &[Attr]) -> (u32, u32) {
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    store(a, "ipu_policy", u64::from(bits::DISABLE)).expect("disable");
    let mut v = fs.volume.lock();
    let ino = v.create(ROOT_INO, b"f", &spec, None).unwrap();
    v.write_file(ino, 0, &alloc::vec![0xA1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let at = v.holder_addr(ino, Holder::Inode, 0).unwrap();
    assert!(at > 1, "the first write did not place a block");
    (ino, at)
}

fn rewrite(fs: &Arc<F2fs>, ino: u32, byte: u8) -> u32 {
    let mut v = fs.volume.lock();
    v.write_file(ino, 0, &alloc::vec![byte; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.holder_addr(ino, Holder::Inode, 0).unwrap()
}

/// Every name, on the MOUNT's own surface — not just in this group's own list,
/// which would pass whether the group were reachable from `mount_attrs` or not.
#[test]
fn every_placement_control_is_published_and_writable() {
    let fs = mounted();
    let published = crate::sysfs::mount_attrs(&fs);
    for name in ["ipu_policy", "min_ipu_util", "min_fsync_blocks", "min_ssr_sections"] {
        let a = published.iter().find(|a| a.dir == "vda" && a.name == name)
            .unwrap_or_else(|| panic!("/sys/fs/f2fs/vda/{name} is not published"));
        assert!(a.store.is_some(), "{name} is not writable");
    }
}

/// What a mount of the fixture settled on, reported through the files.
#[test]
fn the_controls_report_what_the_mount_settled_on() {
    let fs = mounted();
    let a = attrs(&fs);
    // Sixteen megabytes is a SMALL volume, so the mount armed the whole set.
    assert_eq!(show(&a, "ipu_policy"),
               u64::from(bits::bit(bits::FORCE) | bits::bit(bits::HONOR_OPU_WRITE)));
    assert_eq!(show(&a, "min_ipu_util"), u64::from(crate::place::limits::DEF_MIN_IPU_UTIL));
    assert_eq!(show(&a, "min_fsync_blocks"),
               u64::from(crate::place::limits::DEF_MIN_FSYNC_BLOCKS));
    let reserved = u64::from(fs.volume.lock().reserved_sections());
    assert_eq!(show(&a, "min_ssr_sections"), reserved);
}

/// The armed set written through the file decides where a rewrite lands.
#[test]
fn the_armed_set_written_through_the_file_moves_the_next_rewrite() {
    let fs = mounted();
    let a = attrs(&fs);
    let (ino, first) = with_placed_block(&fs, &a);
    // The control: nothing armed, so the rewrite MOVES.
    let moved = rewrite(&fs, ino, 0xB2);
    assert_ne!(moved, first, "the rewrite kept its address with nothing armed");
    // Armed through the file, the rewrite lands back where it lies.
    store(&a, "ipu_policy", u64::from(bits::bit(bits::FORCE))).expect("arm");
    assert_eq!(rewrite(&fs, ino, 0xC3), moved, "the armed set did not reach the write");
}

/// The utilisation threshold written through the file is the one the arm
/// compares against.
///
/// Asserted at the decision's own input rather than at an address, because the
/// fixture's occupancy is a fraction of a percent and reports as ZERO — so no
/// threshold this attribute can carry is below it, and the arm cannot be made
/// to fire at this geometry. The comparison itself is pinned in
/// `tests/place/ipu.rs`; what is pinned here is that the written value is what
/// that comparison reads.
#[test]
fn the_utilisation_threshold_reaches_the_arm_that_reads_it() {
    let fs = mounted();
    let a = attrs(&fs);
    let (ino, at) = with_placed_block(&fs, &a);
    store(&a, "ipu_policy", u64::from(bits::bit(bits::UTIL))).expect("arm");
    for want in [0u32, 41, u32::MAX] {
        store(&a, "min_ipu_util", u64::from(want)).expect("store");
        let v = fs.volume.lock();
        let inode = v.read_inode(ino).unwrap();
        let f = v.ipu_facts(ino, &inode, at, true).unwrap();
        assert_eq!(f.min_ipu_util, want, "the threshold did not reach the decision");
        assert_eq!(f.policy, bits::bit(bits::UTIL), "the armed set did not reach the decision");
    }
}

/// The `fsync` threshold written through the file decides whether a full sync
/// of a short tail asks for its pages in place.
#[test]
fn the_fsync_threshold_reaches_the_sync_that_reads_it() {
    let fs = mounted();
    let a = attrs(&fs);
    let (ino, at) = with_placed_block(&fs, &a);
    store(&a, "ipu_policy", u64::from(bits::bit(bits::FSYNC))).expect("arm");
    // No tail is short enough, so the full sync places the page elsewhere.
    // Asserted in BOTH directions: a threshold that never reached the sync
    // would leave the default in force, under which both syncs stay in place
    // and an equality-only test could not fail.
    store(&a, "min_fsync_blocks", 0).expect("store");
    let moved = {
        let mut v = fs.volume.lock();
        v.write_file(ino, 0, &alloc::vec![0xB2u8; BLKSIZE]).unwrap();
        v.fsync(ino).unwrap();
        v.holder_addr(ino, Holder::Inode, 0).unwrap()
    };
    assert_ne!(moved, at, "a zero threshold did not reach the sync");
    // One page is inside the raised threshold, so the sync keeps the address.
    store(&a, "min_fsync_blocks", 64).expect("store");
    let after = {
        let mut v = fs.volume.lock();
        v.write_file(ino, 0, &alloc::vec![0xC3u8; BLKSIZE]).unwrap();
        v.fsync(ino).unwrap();
        v.holder_addr(ino, Holder::Inode, 0).unwrap()
    };
    assert_eq!(after, moved, "the fsync threshold did not reach the sync");
}

/// The recycling floor written through the file is the one the pressure
/// decision compares against.
#[test]
fn the_recycling_floor_reaches_the_pressure_decision() {
    let fs = mounted();
    let a = attrs(&fs);
    store(&a, "min_ssr_sections", 9).expect("store");
    assert_eq!(show(&a, "min_ssr_sections"), 9);
    let mut v = fs.volume.lock();
    v.load_segments().unwrap();
    assert_eq!(v.ssr_state().min_ssr_sections, 9, "the floor did not reach the decision");
}

/// Every refusal is the decision module's own, taken before the value is
/// stored: a refused write leaves the file reporting what is still in force.
#[test]
fn a_refused_value_is_not_stored() {
    let fs = mounted();
    let a = attrs(&fs);
    let armed = show(&a, "ipu_policy");
    assert!(store(&a, "ipu_policy", u64::from(bits::bit(bits::MAX))).is_err());
    assert!(store(&a, "ipu_policy", u64::from(u32::MAX) + 1).is_err());
    assert_eq!(show(&a, "ipu_policy"), armed);
    for name in ["min_ipu_util", "min_fsync_blocks", "min_ssr_sections"] {
        let was = show(&a, name);
        assert!(store(&a, name, u64::from(u32::MAX) + 1).is_err(), "{name} took a wide value");
        assert_eq!(show(&a, name), was, "{name} kept a refused value");
        // The width is the ONLY bound: a threshold no count can reach turns the
        // arm that reads it off, which is a legitimate thing to ask for.
        assert!(store(&a, name, u64::from(u32::MAX)).is_ok(), "{name} refused a whole word");
    }
}
