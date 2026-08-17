//! Every figure in `iostat_info` reaches it from a real I/O site.
//!
//! Asserted on the RENDERED BODY, never on the counter behind it. A counter
//! raised into a field the report does not print is a number nobody can read,
//! and the report is the whole deliverable — so the check is the same thing a
//! tool would parse.
//!
//! The row labels repeat across sections: `app buffered data`, `fs data` and
//! `fs gc data` each name a write row and a read row, exactly as upstream's
//! format does. Every lookup here is therefore scoped to a section, because a
//! test that took the first match would pass while a write was being charged
//! to a read.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::mode::S_IFREG;
use crate::stats::iostat_info_body;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{le32, BLKSIZE, BLKS_PER_SEG, CURSEG_WARM_DATA, I_COMPRESS_ALGORITHM, I_FLAGS,
                  I_LOG_CLUSTER_SIZE};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 11);

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// A writable volume with accounting already on, so that everything the test
/// then does is measured and nothing the fixture did is.
fn measured() -> Volume<MemImage> {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.set_iostat_enabled(true);
    v
}

/// The report as a tool would read it. # C: O(N kinds)
fn body(v: &Volume<MemImage>) -> String {
    String::from_utf8(iostat_info_body(&v.counters().iostat, 7)).expect("utf-8")
}

/// One row's `(bytes, count)` from the named section.
///
/// The section is part of the lookup because the labels are not unique across
/// them; searching the whole body would let a write answer for a read.
/// # C: O(len)
fn row(body: &str, section: &str, label: &str) -> (u64, u64) {
    let mut in_section = false;
    for line in body.lines() {
        if line.starts_with('[') { in_section = line == section; continue; }
        if !in_section { continue; }
        let Some(rest) = line.strip_prefix(&alloc::format!("{label}:")) else { continue };
        let f: Vec<&str> = rest.split_whitespace().collect();
        return (f[0].parse().unwrap(), f[1].parse().unwrap());
    }
    panic!("no row {label} in {section}\n{body}");
}

/// The order histogram, which says how big the reads served were.
/// # C: O(len)
fn folio_orders(body: &str) -> Vec<u64> {
    let line = body.lines().find(|l| l.starts_with("fs read folio order:")).expect("the histogram");
    line.split_whitespace().skip(4).map(|n| n.parse().unwrap()).collect()
}

/// Nothing is measured until a reader asks for it, and the empty body says
/// exactly that — as against a table of zeroes, which would say measurement
/// ran and found no traffic.
#[test]
fn a_mount_nobody_asked_to_measure_reports_nothing() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![7u8; BLKSIZE]).unwrap();
    v.commit().unwrap();
    assert!(body(&v).is_empty(), "an unasked-for measurement reported something");
}

/// An application's write is charged to the application, and to the two
/// filesystem-side writes it costs: the data block, and the node that has to
/// name it.
#[test]
fn one_file_write_charges_the_application_and_the_writes_it_costs() {
    let mut v = measured();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![7u8; BLKSIZE]).unwrap();
    // The application's own figure is charged by the write; the blocks it
    // costs are charged where they are chosen, which is at writeback.
    v.sync_data().unwrap();
    let b = body(&v);
    assert_eq!(row(&b, "[WRITE]", "app buffered data"), (BLKSIZE as u64, 1));
    // The rollup is the sum of its parts and no site raises it directly.
    let (bytes, _) = row(&b, "[WRITE]", "app buffered data");
    assert_eq!(bytes, BLKSIZE as u64);
    let (data_bytes, data_count) = row(&b, "[WRITE]", "fs data");
    assert_eq!(data_bytes, data_count * BLKSIZE as u64);
    assert!(data_count >= 1, "the page itself was never charged");
    let (_, node_count) = row(&b, "[WRITE]", "fs node");
    assert!(node_count >= 1, "the inode naming the page was never charged");
}

/// A write is the application's traffic; the cleaner's copy of the same block
/// is not, and the two must not land in one figure.
#[test]
fn the_cleaners_copies_are_charged_to_the_cleaner_and_not_to_the_file() {
    let mut v = measured();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![7u8; 4 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let addr = match v.map_block(&v.read_inode(ino).unwrap(), ino, 0).unwrap() {
        crate::volume::map::Mapped::At(a) => a,
        _ => panic!("the file's block is not a block"),
    };
    let victim = (addr - v.super_block().main_blkaddr) / BLKS_PER_SEG;
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    // From here on, only the cleaner writes data.
    v.set_iostat_enabled(false);
    v.set_iostat_enabled(true);
    let moved = v.gc_segment(victim).unwrap();
    assert!(moved > 0, "the fixture gave the cleaner nothing to do");
    let b = body(&v);
    let (gc_bytes, gc_count) = row(&b, "[WRITE]", "fs gc data");
    assert_eq!(gc_count, u64::from(moved), "one charge per block moved");
    assert_eq!(gc_bytes, u64::from(moved) * BLKSIZE as u64);
    assert_eq!(row(&b, "[WRITE]", "fs data").1, 0, "a copy is not the file's own write");
    assert_eq!(row(&b, "[WRITE]", "app buffered data").1, 0, "nobody asked for this");
    // The read side of the same move is charged twice on purpose: it is a
    // data block read, and it is a block the cleaner read.
    assert_eq!(row(&b, "[READ]", "fs gc data").1, u64::from(moved));
    assert_eq!(row(&b, "[READ]", "fs data").1, u64::from(moved));
}

/// A checkpoint's metadata writes are the checkpoint's, and are told apart
/// from every other metadata write — which is the only thing the address they
/// go to cannot say.
#[test]
fn a_checkpoints_metadata_writes_are_charged_to_the_checkpoint() {
    let mut v = measured();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![7u8; BLKSIZE]).unwrap();
    let before = row(&body(&v), "[WRITE]", "fs cp meta");
    assert_eq!(before.1, 0, "no checkpoint has run yet");
    v.commit().unwrap();
    let b = body(&v);
    let (bytes, count) = row(&b, "[WRITE]", "fs cp meta");
    assert!(count > 0, "the pack's own blocks were never charged");
    assert_eq!(bytes, count * BLKSIZE as u64);
    // The mark comes down again, so the next ordinary metadata write is not
    // charged to a checkpoint that is no longer running.
    let after_cp = row(&b, "[WRITE]", "fs cp meta").1;
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    let b = body(&v);
    assert_eq!(row(&b, "[WRITE]", "fs cp meta").1, after_cp, "the mark outlived the checkpoint");
    assert!(row(&b, "[WRITE]", "fs meta").1 > 0, "the summary block went uncharged");
}

/// A metadata read is classified by where the block lives, which is the same
/// derivation the write path uses to call a block metadata.
#[test]
fn a_read_outside_the_main_area_is_charged_as_metadata() {
    let v = measured();
    let sit_blkaddr = v.super_block().sit_blkaddr;
    let before = row(&body(&v), "[READ]", "fs meta").1;
    v.read_block(sit_blkaddr).unwrap();
    let b = body(&v);
    assert_eq!(row(&b, "[READ]", "fs meta").1, before + 1);
    assert_eq!(row(&b, "[READ]", "fs node").1, 0, "a table block is not a node");
    assert_eq!(row(&b, "[READ]", "fs data").1, 0, "a table block is not file data");
}

/// A node block sits in the main area beside file data, so its address cannot
/// say what it is; the reader that knows says so.
#[test]
fn a_node_read_is_charged_as_a_node_and_not_as_data() {
    let v = measured();
    let before = row(&body(&v), "[READ]", "fs node").1;
    v.read_inode(ROOT_INO).unwrap();
    let b = body(&v);
    assert_eq!(row(&b, "[READ]", "fs node").1, before + 1);
    assert_eq!(row(&b, "[READ]", "fs data").1, 0);
}

/// The application's read is what the caller asked for; the block reads under
/// it are what the medium did. Both are wanted and they are not the same
/// number — a read served from a hole moves no block at all.
#[test]
fn an_application_read_and_the_blocks_under_it_are_charged_apart() {
    let mut v = measured();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![7u8; 2 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    // A page a write left in the mapping answers the read without the medium,
    // so the figure this measures — what the medium moved — needs a cold one.
    v.data_cache.forget_inode(ino);
    v.set_iostat_enabled(false);
    v.set_iostat_enabled(true);
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; 100];
    assert_eq!(v.read_file(&inode, ino, 0, &mut buf).unwrap(), 100);
    let b = body(&v);
    assert_eq!(row(&b, "[READ]", "app buffered data"), (100, 1), "what the caller asked for");
    assert_eq!(row(&b, "[READ]", "fs data"), (BLKSIZE as u64, 1), "what the medium moved");
    // Every read this build serves is one block, so the histogram's first
    // bucket is where they land and no other bucket ever fills.
    let orders = folio_orders(&b);
    assert_eq!(orders[0], 1);
    assert!(orders[1..].iter().all(|&n| n == 0));
}

/// A cache flush carries no bytes, so its byte total is zero by construction
/// and its count is the figure worth having.
///
/// A checkpoint on a volume of ONE member charges none: that member carries the
/// pack, so its ordering is the commit block's own pre-flush and there is no
/// separate barrier to count. The figure this row exists for is the barrier an
/// `fsync` chain owes, and it is charged where it is issued — which is only at a
/// medium that has a cache to empty.
#[test]
fn a_barrier_flush_is_counted_and_carries_no_bytes() {
    let bytes = test_image::with_root().finish();
    let img = sectors::MemImage::from_bytes(BLKSIZE as u32, bytes).with_write_cache();
    let mut v = crate::volume::Volume::mount_with(img, crate::opts::Options::defaults(), true).unwrap();
    assert!(v.options().barrier, "the fixture must be taking barriers");
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![7u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    v.write_file(ino, 0, b"x").unwrap();
    v.sync_data().unwrap();
    v.set_iostat_enabled(true);
    assert!(!v.fsync(ino).unwrap().needed(), "the fixture must take the chain path");
    assert_eq!(row(&body(&v), "[OTHER]", "fs flush"), (0, 1));
}

/// The same checkpoint on a volume of one member, where the commit block's own
/// pre-flush is the whole of the ordering: nothing separate is issued, so
/// nothing is counted.
#[test]
fn a_single_member_checkpoint_charges_no_separate_barrier() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![7u8; BLKSIZE]).unwrap();
    v.set_iostat_enabled(true);
    v.commit().unwrap();
    assert_eq!(row(&body(&v), "[OTHER]", "fs flush"), (0, 0));
}

/// A compressed file's traffic is counted under both its kinds, because the
/// compressed figure answers what share of the traffic was compressed and a
/// partition of the total could not.
#[test]
fn compressed_traffic_appears_under_its_plain_kind_and_its_own() {
    let mut b = test_image::with_root();
    // Without the feature the inode's compression fields are not compression
    // fields at all and nothing acts on them.
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut v = b.mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"c", &spec(), None).unwrap();
    v.stamp_inode(ino, |b| {
        let f = le32(b, I_FLAGS).unwrap_or(0) | crate::flags::F2FS_COMPR_FL;
        crate::volume::dnode::put32(b, I_FLAGS, f);
        b[I_COMPRESS_ALGORITHM] = crate::compress::algo::COMPRESS_LZ4;
        b[I_LOG_CLUSTER_SIZE] = 2;
    })
    .unwrap();
    v.set_iostat_enabled(true);
    let data = vec![9u8; 8 * BLKSIZE];
    v.write_file(ino, 0, &data).unwrap();
    let b = body(&v);
    assert_eq!(row(&b, "[WRITE]", "app buffered data").0, data.len() as u64);
    assert_eq!(row(&b, "[WRITE]", "app buffered cdata").0, data.len() as u64,
               "the application's write is compressed traffic too");
    let (plain, plain_n) = row(&b, "[WRITE]", "fs data");
    let (compressed, compressed_n) = row(&b, "[WRITE]", "fs cdata");
    assert!(compressed_n > 0, "the cluster's stored blocks were never charged as compressed");
    assert_eq!(compressed_n, plain_n, "every stored block is both");
    assert_eq!(plain, compressed);
}

/// Turning the control off forgets the totals, which is what makes measuring
/// one window possible: totals carried across the switch would add the last
/// window to the new one.
#[test]
fn turning_the_control_off_forgets_what_was_measured() {
    let mut v = measured();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![7u8; BLKSIZE]).unwrap();
    assert!(row(&body(&v), "[WRITE]", "app buffered data").1 > 0);
    v.set_iostat_enabled(false);
    assert!(body(&v).is_empty(), "an off mount must report nothing");
    v.set_iostat_enabled(true);
    assert_eq!(row(&body(&v), "[WRITE]", "app buffered data"), (0, 0),
               "the previous window survived into the new one");
}

/// Accounting is off unless it is asked for, because it costs a pair of
/// additions on every block and one inode read on every application write.
#[test]
fn accounting_is_off_on_a_fresh_mount() {
    let v = test_image::with_root().mount_rw().unwrap();
    assert!(!v.iostat_enabled());
}
