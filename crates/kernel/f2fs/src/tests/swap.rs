//! Swap areas: what refuses one, and the runs one hands over.

use super::extents::{self, Extent, SwapMap};
use super::policy::{self, SwapFacts};
use crate::mode::S_IFREG;
use crate::opts::{Mode, Options};
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 7);
/// Higher than any fixture's block count, so the ceiling never decides.
const NO_CEILING: u64 = 1 << 30;

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn ok_facts() -> SwapFacts {
    SwapFacts { is_reg: true, ro_mount: false, lfs_mode: false, blkzoned: false,
                compressed_undisableable: false }
}

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

// ------------------------------------------------------------------- ladder

#[test]
fn only_a_regular_file_may_be_a_swap_area() {
    let f = SwapFacts { is_reg: false, ..ok_facts() };
    assert_eq!(policy::swap_activate(&f), Err(Errno::Einval));
}

#[test]
fn a_read_only_mount_hosts_no_swap_area() {
    let f = SwapFacts { ro_mount: true, ..ok_facts() };
    assert_eq!(policy::swap_activate(&f), Err(Errno::Erofs));
}

#[test]
fn the_type_refusal_comes_before_the_mounts() {
    let f = SwapFacts { is_reg: false, ro_mount: true, ..ok_facts() };
    assert_eq!(policy::swap_activate(&f), Err(Errno::Einval));
}

#[test]
fn a_strictly_out_of_place_mount_hosts_no_swap_area() {
    let f = SwapFacts { lfs_mode: true, ..ok_facts() };
    assert_eq!(policy::swap_activate(&f), Err(Errno::Einval));
    // Unless the drive imposes the same rule on everything anyway.
    let z = SwapFacts { lfs_mode: true, blkzoned: true, ..ok_facts() };
    assert_eq!(policy::swap_activate(&z), Ok(()));
}

#[test]
fn compression_that_cannot_come_off_refuses_the_area() {
    let f = SwapFacts { compressed_undisableable: true, ..ok_facts() };
    assert_eq!(policy::swap_activate(&f), Err(Errno::Einval));
}

// ------------------------------------------------------------------ extents

#[test]
fn a_run_is_aligned_only_when_both_ends_are() {
    // Starts on a boundary and fills whole sections.
    assert!(extents::section_aligned(1000, 1000, 512, 512));
    assert!(extents::section_aligned(1512, 1000, 1024, 512));
    // Starts mid-section.
    assert!(!extents::section_aligned(1001, 1000, 512, 512));
    // Ends mid-section.
    assert!(!extents::section_aligned(1000, 1000, 511, 512));
}

#[test]
fn a_length_rounds_up_to_whole_sections() {
    assert_eq!(extents::roundup_sections(1, 512), 512);
    assert_eq!(extents::roundup_sections(512, 512), 512);
    assert_eq!(extents::roundup_sections(513, 512), 1024);
    assert_eq!(extents::roundup_sections(0, 512), 0);
}

#[test]
fn consecutive_runs_are_reported_as_one() {
    let mut m = SwapMap::default();
    m.push(0, 100, 4);
    m.push(4, 104, 4);
    assert_eq!(m.extents, vec![Extent { lblk: 0, pblk: 100, blocks: 8 }]);
    // A gap on the medium is a second run even when the file is contiguous.
    m.push(8, 200, 4);
    assert_eq!(m.extents.len(), 2);
    // A gap in the file is a second run even when the medium is contiguous.
    let mut n = SwapMap::default();
    n.push(0, 100, 4);
    n.push(9, 104, 4);
    assert_eq!(n.extents.len(), 2);
}

#[test]
fn a_run_resolves_the_blocks_it_covers_and_no_others() {
    let mut m = SwapMap::default();
    m.push(0, 100, 4);
    m.push(10, 200, 2);
    assert_eq!(m.resolve(0), Some(100));
    assert_eq!(m.resolve(3), Some(103));
    assert_eq!(m.resolve(4), None);
    assert_eq!(m.resolve(11), Some(201));
    assert_eq!(m.resolve(12), None);
}

#[test]
fn the_header_block_is_not_part_of_the_area() {
    let mut m = SwapMap::default();
    m.seal(8, Some(100), 107);
    assert_eq!(m.max, 8);
    assert_eq!(m.pages, 7);
    assert_eq!(m.span, 8);
    // A file that yielded nothing reports an empty area rather than a full one.
    let mut e = SwapMap::default();
    e.seal(0, None, 0);
    assert_eq!((e.max, e.pages, e.span), (1, 0, 0));
}

// ------------------------------------------------------------------- volume

/// A pinned file holding one whole section, which is what a swapfile is.
fn swapfile() -> (Volume<MemImage>, u32, u64) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"swap", &spec(), None).unwrap();
    v.set_pin_file(ino, 1).unwrap();
    let sec = u64::from(v.blks_per_sec());
    v.expand_pinned(ino, 0, sec * BLKSIZE as u64).unwrap();
    (v, ino, sec)
}

#[test]
fn a_section_aligned_file_activates_as_one_run() {
    let (mut v, ino, sec) = swapfile();
    let map = v.swap_activate(ino, NO_CEILING).unwrap();
    assert_eq!(map.extents.len(), 1);
    assert_eq!(map.extents[0].blocks, sec);
    assert_eq!(map.not_aligned, 0);
    assert_eq!(map.max, sec);
    assert_eq!(map.pages, sec - 1);
    // The span measures the blocks past the header, and the header is inside
    // this run: one run means nothing is left to measure.
    assert_eq!(map.span, 0);
}

#[test]
fn activation_pins_the_file_and_the_pin_survives_a_remount() {
    let (mut v, ino, _) = swapfile();
    v.set_pin_file(ino, 0).unwrap();
    assert!(!v.is_pinned_ino(ino).unwrap());
    v.swap_activate(ino, NO_CEILING).unwrap();
    assert!(v.is_pinned_ino(ino).unwrap());
    let v = remount(v);
    assert!(v.is_pinned_ino(ino).unwrap());
}

#[test]
fn deactivation_lets_the_cleaner_have_the_blocks_again() {
    let (mut v, ino, _) = swapfile();
    v.swap_activate(ino, NO_CEILING).unwrap();
    v.swap_deactivate(ino).unwrap();
    assert!(!v.is_pinned_ino(ino).unwrap());
    let v = remount(v);
    assert!(!v.is_pinned_ino(ino).unwrap());
}

#[test]
fn the_addresses_handed_over_are_the_files_own() {
    let (mut v, ino, sec) = swapfile();
    let map = v.swap_activate(ino, NO_CEILING).unwrap();
    let inode = v.read_inode(ino).unwrap();
    for i in 0..sec {
        let want = match v.map_block(&inode, ino, i).unwrap() {
            crate::volume::map::Mapped::At(a) => a,
            other => panic!("block {i} is {other:?}"),
        };
        assert_eq!(map.resolve(i), Some(want));
    }
}

#[test]
fn the_addresses_are_still_the_files_own_after_a_remount() {
    let (mut v, ino, sec) = swapfile();
    let map = v.swap_activate(ino, NO_CEILING).unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    for i in 0..sec {
        let want = match v.map_block(&inode, ino, i).unwrap() {
            crate::volume::map::Mapped::At(a) => a,
            other => panic!("block {i} is {other:?}"),
        };
        assert_eq!(map.resolve(i), Some(want), "block {i} moved across a remount");
    }
}

#[test]
fn a_file_with_a_hole_where_the_walk_starts_is_refused() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"sparse", &spec(), None).unwrap();
    // Written past the front, so the file's first block has no address at all
    // and there is nothing to hand the paging code for it.
    v.write_file(ino, BLKSIZE as u64 * 4, b"far out").unwrap();
    assert_eq!(v.swap_activate(ino, NO_CEILING), Err(Errno::Einval));
}

#[test]
fn a_directory_is_refused_by_the_volume_too() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let d = v.create(ROOT_INO, b"d",
                     &NewInode { mode: crate::mode::S_IFDIR | 0o755, ..spec() }, None).unwrap();
    assert_eq!(v.swap_activate(d, NO_CEILING), Err(Errno::Einval));
}

#[test]
fn a_strictly_out_of_place_mount_is_refused_by_the_volume_too() {
    let mut opts = Options::defaults();
    opts.mode = Mode::Lfs;
    let mut v = test_image::with_root().mount_opts(opts).unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    assert_eq!(v.swap_activate(ino, NO_CEILING), Err(Errno::Einval));
}

#[test]
fn a_read_only_mount_is_refused_by_the_volume_too() {
    let (v, ino, _) = swapfile();
    let bytes = { let mut v = v; v.commit().unwrap(); v.into_source().snapshot() };
    let mut ro = Volume::mount_with(
        MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), false).unwrap();
    assert_eq!(ro.swap_activate(ino, NO_CEILING), Err(Errno::Erofs));
}

#[test]
fn a_file_whose_length_is_not_whole_sections_is_refused_rather_than_retried_forever() {
    // The alignment walk moves a run and looks again. A file whose SIZE is
    // not a whole number of sections can never satisfy the second half of the
    // alignment test however often it is moved, so the walk gives up instead
    // of moving the same run for ever.
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"odd", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![4u8; BLKSIZE * 2]).unwrap();
    assert_eq!(v.swap_activate(ino, NO_CEILING), Err(Errno::Einval));
}

#[test]
fn a_ceiling_below_the_file_clips_the_area() {
    let (mut v, ino, sec) = swapfile();
    let map = v.swap_activate(ino, sec / 2).unwrap();
    assert_eq!(map.max, sec / 2);
    assert_eq!(map.pages, sec / 2 - 1);
    assert_eq!(map.resolve(sec / 2), None);
}

#[test]
fn moving_a_run_puts_it_on_a_section_boundary() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"m", &spec(), None).unwrap();
    let region = v.read_inode(ino).unwrap().inline_data_span().1;
    v.write_file(ino, 0, &vec![6u8; region + 1]).unwrap();
    let sb_main = v.super_block().main_blkaddr;
    let sec = u64::from(v.blks_per_sec());
    let before = match v.map_block(&v.read_inode(ino).unwrap(), ino, 0).unwrap() {
        crate::volume::map::Mapped::At(a) => a,
        other => panic!("{other:?}"),
    };
    // A file that already has blocks cannot be pinned; moving them is how a
    // swapfile written the ordinary way becomes one that can be.
    assert_eq!(v.set_pin_file(ino, 1), Err(Errno::Efbig));
    v.migrate_pinned_range(ino, 0, 1).unwrap();
    let after = match v.map_block(&v.read_inode(ino).unwrap(), ino, 0).unwrap() {
        crate::volume::map::Mapped::At(a) => a,
        other => panic!("{other:?}"),
    };
    assert_eq!(u64::from(after - sb_main) % sec, 0, "the run was not moved to a boundary");
    assert_ne!(after, before, "the run did not move at all");
    // The bytes came with it.
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; 8];
    v.read_file(&inode, ino, 0, &mut buf).unwrap();
    assert_eq!(buf, vec![6u8; 8]);
}
