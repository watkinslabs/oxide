//! The volume-owned controls, read and written through the same `show` and
//! `store` a tool would run.
//!
//! Two things are being checked and only one of them is the arithmetic. The
//! other is that the published surface and the machinery agree: a value the
//! attribute accepts must be a value the decision behind it will use, and a
//! value the machinery would reject must be refused at the file rather than
//! stored and quietly ignored.

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::VfsError;

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

#[test]
fn every_volume_owned_control_is_writable() {
    let fs = mounted();
    let a = attrs(&fs);
    for name in ["ram_thresh", "ra_nid_pages", "gc_pin_file_thresh", "max_read_extent_count", "last_age_weight",
                 "hot_data_age_threshold", "warm_data_age_threshold",
                 "gc_segment_mode", "gc_reclaimed_segments",
                 "atgc_candidate_ratio", "atgc_candidate_count",
                 "atgc_age_weight", "atgc_age_threshold"] {
        assert!(find(&a, name).store.is_some(), "{name} is not writable");
    }
}

#[test]
fn reclaimed_segment_report_uses_one_selected_live_counter() {
    let fs = mounted();
    let a = attrs(&fs);
    {
        let v = fs.volume.lock();
        let mut counters = v.counters.borrow_mut();
        counters.gc_reclaimed_segs[crate::stats::counters::gc_mode::NORMAL] = 3;
        counters.gc_reclaimed_segs[crate::stats::counters::gc_mode::IDLE_CB] = 7;
    }
    assert_eq!(show(&a, "gc_segment_mode"), 0);
    assert_eq!(show(&a, "gc_reclaimed_segments"), 3);
    store(&a, "gc_segment_mode", 1).expect("select idle-cb");
    assert_eq!(show(&a, "gc_reclaimed_segments"), 7);
    store(&a, "gc_reclaimed_segments", 0).expect("reset selected total");
    assert_eq!(show(&a, "gc_reclaimed_segments"), 0);
    store(&a, "gc_segment_mode", 0).expect("select normal");
    assert_eq!(show(&a, "gc_reclaimed_segments"), 3, "reset crossed modes");
}

#[test]
fn reclaimed_segment_controls_refuse_invalid_writes() {
    let fs = mounted();
    let a = attrs(&fs);
    assert!(store(&a, "gc_segment_mode", crate::stats::counters::gc_mode::MAX as u64).is_err());
    assert!(store(&a, "gc_reclaimed_segments", 1).is_err());
}

#[test]
fn pin_collision_threshold_is_live_and_linux_bounded() {
    let fs = mounted();
    let a = attrs(&fs);
    assert_eq!(show(&a, "gc_pin_file_thresh"),
               u64::from(crate::pin::policy::GC_PIN_FILE_THRESHOLD));
    store(&a, "gc_pin_file_thresh", 0).expect("Linux accepts zero");
    assert_eq!(fs.volume.lock().gc_pin_file_threshold(), 0);
    assert_eq!(show(&a, "gc_pin_file_thresh"), 0);
    assert!(store(&a, "gc_pin_file_thresh",
                  u64::from(crate::pin::policy::MAX_GC_FAILED_PINNED_FILES) + 1).is_err());
    assert_eq!(show(&a, "gc_pin_file_thresh"), 0, "a refused write changed the policy");
}

/// The point of the knob: what is written is what the machinery then holds.
/// A control that stored somewhere the decision does not read would pass a
/// read-back test against its own copy and change nothing.
#[test]
fn a_stored_value_reaches_the_cache_the_decision_reads() {
    let fs = mounted();
    let a = attrs(&fs);
    store(&a, "max_read_extent_count", 77).expect("store");
    assert_eq!(fs.volume.lock().extents().max_read_extent_count(), 77);
    assert_eq!(show(&a, "max_read_extent_count"), 77);

    store(&a, "last_age_weight", 42).expect("store");
    assert_eq!(fs.volume.lock().extents().last_age_weight(), 42);

    store(&a, "ram_thresh", 9).expect("store");
    assert_eq!(fs.volume.lock().nid_ram_thresh(), 9);

    store(&a, "ra_nid_pages", 12).expect("store");
    assert_eq!(fs.volume.lock().ra_nid_pages(), 12);
    assert_eq!(show(&a, "ra_nid_pages"), 12);
}

#[test]
fn ra_nid_pages_accepts_zero_and_refuses_values_outside_u32() {
    let fs = mounted();
    let a = attrs(&fs);
    assert_eq!(show(&a, "ra_nid_pages"), 0, "Linux default disables the advisory read-ahead");
    store(&a, "ra_nid_pages", 0).expect("zero is the Linux default");
    assert!(store(&a, "ra_nid_pages", u64::from(u32::MAX) + 1).is_err());
    assert_eq!(show(&a, "ra_nid_pages"), 0);
}

#[test]
fn a_stored_age_control_reaches_the_policy_that_costs_candidates() {
    let fs = mounted();
    let a = attrs(&fs);
    store(&a, "atgc_candidate_ratio", 35).expect("store");
    store(&a, "atgc_candidate_count", 4).expect("store");
    store(&a, "atgc_age_weight", 10).expect("store");
    store(&a, "atgc_age_threshold", 1234).expect("store");
    let v = fs.volume.lock();
    let am = v.atgc();
    assert_eq!((am.candidate_ratio, am.max_candidate_count, am.age_weight, am.age_threshold),
               (35, 4, 10, 1234));
}

#[test]
fn a_percentage_control_refuses_more_than_the_whole() {
    let fs = mounted();
    let a = attrs(&fs);
    for name in ["ram_thresh", "last_age_weight", "atgc_candidate_ratio", "atgc_age_weight"] {
        assert!(store(&a, name, 101).is_err(), "{name} took 101");
    }
}

/// A refused write leaves the value it named exactly as it was. A control that
/// half-applied a rejected value would report the refusal and act on the value.
#[test]
fn a_refused_write_changes_nothing() {
    let fs = mounted();
    let a = attrs(&fs);
    let before = show(&a, "last_age_weight");
    assert!(store(&a, "last_age_weight", 900).is_err());
    assert_eq!(show(&a, "last_age_weight"), before);
    assert_eq!(fs.volume.lock().extents().last_age_weight(), before as u32);
}

/// The two age boundaries cut one line into three parts. A pair that crossed
/// would leave one part empty and the other two overlapping, so every block
/// would classify twice or not at all.
#[test]
fn the_two_age_boundaries_may_not_cross() {
    let fs = mounted();
    let a = attrs(&fs);
    let warm = show(&a, "warm_data_age_threshold");
    let hot = show(&a, "hot_data_age_threshold");
    assert!(hot < warm);
    assert!(store(&a, "hot_data_age_threshold", warm).is_err());
    assert!(store(&a, "hot_data_age_threshold", warm + 1).is_err());
    assert!(store(&a, "warm_data_age_threshold", hot).is_err());
    assert!(store(&a, "hot_data_age_threshold", 0).is_err());
    // Room in between is accepted, in either order.
    store(&a, "warm_data_age_threshold", warm * 2).expect("raise the warm boundary");
    store(&a, "hot_data_age_threshold", warm + 1).expect("hot below the new warm");
}

#[test]
fn a_zero_run_ceiling_is_refused() {
    let fs = mounted();
    let a = attrs(&fs);
    assert!(store(&a, "max_read_extent_count", 0).is_err());
    assert!(store(&a, "ram_thresh", 0).is_err());
}

/// The report says whether the policy is RUNNING, which on a volume too young
/// for it is not the same as whether the mount asked for it.
#[test]
fn the_age_policy_reports_what_the_mount_settled_on() {
    let mut opts = Options::defaults();
    opts.atgc = true;
    let bytes = test_image::with_root().finish();
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    let fs = F2fs::open_with(dev, "/dev/vda", true, opts).expect("mount");
    // A freshly built image has no elapsed time, so the policy cannot run.
    assert!(fs.volume.lock().options().atgc);
    assert!(!fs.volume.lock().atgc_enabled());
    let a = super::super::volume::attrs(&fs, "vda");
    assert_eq!(show(&a, "atgc_enabled"), 0);
}

/// The dirty-node-table share written through the file is the one the balance
/// decision compares against, and it is bounded as a percentage.
#[test]
fn the_dirty_node_share_reaches_the_decision_that_reads_it() {
    let fs = mounted();
    let a = attrs(&fs);
    assert_eq!(show(&a, "dirty_nats_ratio"),
               u64::from(crate::freenid::limits::DEF_DIRTY_NATS_RATIO));
    store(&a, "dirty_nats_ratio", 40).expect("accepted");
    assert_eq!(fs.volume.lock().dirty_nats_ratio(), 40, "the decision reads this");
    assert_eq!(show(&a, "dirty_nats_ratio"), 40);
    // A percentage, so a whole share is the bound; zero would make every cached
    // entry excessive and every operation owe a checkpoint.
    for bad in [0u64, 101, u64::from(u32::MAX)] {
        assert!(store(&a, "dirty_nats_ratio", bad).is_err(), "{bad} was accepted");
    }
    assert_eq!(fs.volume.lock().dirty_nats_ratio(), 40, "a refusal changed it");
    // And the share genuinely decides the live volume answer. The fixture's
    // node table is large, so one create cannot cross even the minimum 1%
    // threshold; create the required real entries rather than editing the
    // accounting fields underneath the decision.
    use crate::bg::balance::excess_dirty_nats_at;
    assert!(excess_dirty_nats_at(10, 100, 10), "a tenth of the table is a tenth");
    assert!(!excess_dirty_nats_at(9, 100, 10));
    assert!(!excess_dirty_nats_at(0, 100, 1), "an empty table is never excessive");
    assert!(excess_dirty_nats_at(1, 100, 1));
    store(&a, "dirty_nats_ratio", 1).expect("minimum accepted ratio");
    {
        let mut v = fs.volume.lock();
        let spec = crate::volume::NewInode { mode: crate::mode::S_IFREG | 0o644, uid: 0, gid: 0,
                                             rdev: 0, now: (1_800_000_000, 0) };
        for i in 0..5000usize {
            if v.excess_dirty_nats() { break; }
            let name = alloc::format!("nat-{i}");
            v.create(crate::test_image::ROOT_INO, name.as_bytes(), &spec, None).unwrap();
        }
        assert!(v.cached_nats() > 0, "a create dirtied no node-table entry");
        assert!(v.excess_dirty_nats(),
                "a real file workload never crossed the minimum dirty-NAT share");
        assert_eq!(v.excess_dirty_nats(),
                   excess_dirty_nats_at(v.cached_nats(), v.max_nid() as usize,
                                        v.dirty_nats_ratio() as usize),
                   "the volume's answer is not the comparison's, at its own share");
    }
}
