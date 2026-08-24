//! The derived reports, read through the same `show` a reader of the file runs.

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;

use crate::fsattr::Attr;
use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image;
use crate::uapi::BLKSIZE;

const BS: u32 = BLKSIZE as u32;

fn mounted() -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    F2fs::open_with(dev, "/dev/vda", true, Options::defaults()).expect("mount")
}

fn show(attrs: &[Attr], name: &str) -> String {
    let a = attrs.iter().find(|a| a.dir == "vda" && a.name == name)
        .unwrap_or_else(|| panic!("no attribute vda/{name}"));
    String::from_utf8((a.show)().expect("show")).expect("utf-8")
}

/// Every report is published, read-only, and answers with a number.
#[test]
fn each_report_is_read_only_and_reads_a_number() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    for name in ["avg_vblocks", "current_atomic_write", "defrag_blocks",
                 "unusable_blocks_per_sec", "max_open_zones"] {
        let a = attrs.iter().find(|a| a.dir == "vda" && a.name == name)
            .unwrap_or_else(|| panic!("no attribute vda/{name}"));
        assert_eq!(a.mode, crate::fsattr::RO, "{name} accepts a write");
        let body = show(&attrs, name);
        assert!(body.ends_with('\n'), "{name} did not end its line");
        body.trim().parse::<u64>().unwrap_or_else(|_| panic!("{name} read {body:?}"));
    }
}

#[test]
fn atomic_peak_is_writable_only_as_a_zero_reset() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    let a = attrs.iter().find(|a| a.name == "peak_atomic_write").expect("published");
    assert_eq!(a.mode, crate::fsattr::RW);
    assert!(a.store.as_ref().unwrap()(b"1\n").is_err());
    a.store.as_ref().unwrap()(b"0\n").expect("reset");
    assert_eq!(show(&attrs, "peak_atomic_write"), "0\n");
}

/// The total is SUMMED from the spans the volume holds, so opening one moves it.
/// A counter kept beside the spans could report a block the span no longer has.
#[test]
fn the_atomic_write_total_follows_the_open_spans() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    let read = || show(&attrs, "current_atomic_write").trim().parse::<u64>().unwrap();
    assert_eq!(read(), 0, "a mount with no span open reported blocks");
    let ino = { fs.volume.lock().atomic_files().len() };
    assert_eq!(ino, 0);
}

/// A volume that is not zoned still answers both zone questions, because each
/// has a value there. An absent attribute would say the question is meaningless.
#[test]
fn an_unzoned_volume_reports_no_dead_room_and_no_open_zone_limit() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    assert!(fs.volume.lock().zones().is_none(), "the test image became zoned");
    assert_eq!(show(&attrs, "unusable_blocks_per_sec"), "0\n");
    // Never the internal unbounded sentinel, which would tell a tool the drive
    // will hold four billion zones open.
    assert_eq!(show(&attrs, "max_open_zones"), "0\n");
    assert_ne!(show(&attrs, "max_open_zones").trim(),
               alloc::format!("{}", crate::zoned::geom::OPEN_ZONES_UNBOUNDED));
}

/// The mean is recomputed from the segment table on the read, so it is an answer
/// about the volume as it stands rather than as it was last sampled.
#[test]
fn the_section_occupancy_mean_agrees_with_a_direct_sample() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    let published = show(&attrs, "avg_vblocks").trim().parse::<u64>().unwrap();
    let direct = {
        let mut v = fs.volume.lock();
        let c = v.counters();
        crate::stats::General::sample(&mut v, &c).expect("sample").avg_vblocks
    };
    assert_eq!(published, direct);
}
