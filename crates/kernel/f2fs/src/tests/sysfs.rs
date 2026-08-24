//! `/sys/fs/f2fs` — the attribute set, and what each attribute reports off a
//! real mounted volume.
//!
//! Every value is read through the same `show` a reader of the file would
//! run, so a test here fails for exactly the reason a reader would see the
//! wrong bytes.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;

use crate::fsattr::Attr;
use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image;
use crate::uapi::BLKSIZE;

use super::{global_attrs, mount_attrs, mount_dir, GLOBAL_DIRS, SUBSYS};

const BS: u32 = BLKSIZE as u32;

fn mounted(source: &str) -> Arc<F2fs> { mounted_rw(source, true) }

fn mounted_rw(source: &str, write: bool) -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    F2fs::open_with(dev, source, write, Options::defaults()).expect("mount")
}

fn find<'a>(attrs: &'a [Attr], dir: &str, name: &str) -> &'a Attr {
    attrs.iter().find(|a| a.dir == dir && a.name == name)
        .unwrap_or_else(|| panic!("no attribute {dir}/{name}"))
}

fn show(attrs: &[Attr], dir: &str, name: &str) -> String {
    let bytes = (find(attrs, dir, name).show)().expect("show");
    String::from_utf8(bytes).expect("utf-8")
}

fn names(attrs: &[Attr], dir: &str) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = attrs.iter().filter(|a| a.dir == dir).map(|a| a.name).collect();
    v.sort();
    v
}

#[test]
fn the_subsystem_is_named_for_the_filesystem() {
    assert_eq!(SUBSYS, "f2fs");
    assert_eq!(GLOBAL_DIRS, ["features", "tuning"]);
}

/// `features/` states what the BUILD can do. Every name must correspond to
/// code that exists, and every entry reads the one word upstream gives.
#[test]
fn the_build_feature_directory_lists_only_implemented_features() {
    let attrs = global_attrs();
    let listed = names(&attrs, "features");
    assert!(listed.contains(&"casefold"));
    assert!(listed.contains(&"compression"));
    assert!(listed.contains(&"verity"));
    assert!(listed.contains(&"quota_ino"));
    // A zoned volume MOUNTS: its geometry is read and its write pointers are
    // reconciled against the logs. Claiming otherwise sent a formatter away
    // from a feature that works.
    assert!(listed.contains(&"block_zoned"));
    // Data and names are both enciphered and deciphered, including under a
    // case-folding directory, where the bucket is the keyed hash of the folded
    // plaintext.
    assert!(listed.contains(&"encryption"));
    assert!(listed.contains(&"encrypted_casefold"));
    // The ioctls exist and reach the volume.
    assert!(listed.contains(&"atomic_write"));
    assert!(listed.contains(&"pin_file"));
    // A no-op at the only block size a volume may state, so the ordinary
    // summary reader reads a packed volume correctly.
    assert!(listed.contains(&"packed_ssa"));
    // The one absence: nothing calls the record that carries an error into the
    // superblock, so a damaged volume looks clean to the next mount.
    assert!(!listed.contains(&"fserror"));
    for a in attrs.iter() {
        assert_eq!(a.mode, crate::fsattr::RO);
        assert_eq!((a.show)().expect("show"), b"supported\n");
    }
}

#[test]
fn a_mounts_directory_is_the_devices_short_name() {
    assert_eq!(mount_dir("/dev/vda"), "vda");
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    assert!(attrs.iter().all(|a| a.dir == "vda" || a.dir.starts_with("vda/")));
}

/// The three directories one mount publishes, and that nothing lands outside
/// them.
#[test]
fn a_mount_publishes_its_own_stat_and_feature_list_directories() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    assert!(!names(&attrs, "vda").is_empty());
    assert_eq!(names(&attrs, "vda/stat"),
               ["cp_status", "issued_discard", "queued_discard", "sb_status",
                "undiscard_blks"]);
    let fl = names(&attrs, "vda/feature_list");
    assert_eq!(fl.len(), 16, "one entry per on-disk feature bit");
    assert!(fl.contains(&"casefold"));
    assert!(fl.contains(&"device_alias"));
    assert!(!fl.contains(&"atomic_write"), "not an on-disk property");
}

/// An attribute is writable exactly when machinery reads what is written to
/// it. Everything else refuses the write rather than accepting and discarding
/// it, which would report a change it had not made.
#[test]
fn an_attribute_is_writable_exactly_when_something_reads_it() {
    let fs = mounted("/dev/vda");
    // Two sets, because the machinery behind them lives in two places: the
    // background threads own their intervals and modes, and the volume owns
    // both extent caches, the free-id cache and age-threshold selection.
    let mut controls: alloc::vec::Vec<&str> =
        crate::bg::knobs::ALL.iter().map(|&k| crate::bg::knobs::name(k)).collect();
    controls.extend(crate::atgc::knobs::ALL.iter().map(|&k| crate::atgc::knobs::name(k)));
    controls.extend(["ram_thresh", "ra_nid_pages", "max_read_extent_count", "last_age_weight",
                     "hot_data_age_threshold", "warm_data_age_threshold", "iostat_enable",
                     "readdir_ra", "dirty_nats_ratio", "gc_segment_mode",
                     "gc_reclaimed_segments", "gc_pin_file_thresh", "reclaim_segments",
                     "gc_valid_thresh_ratio", "migration_window_granularity",
                     "migration_granularity", "dir_level", "seq_file_ra_mul",
                     "max_roll_forward_node_blocks", "max_io_bytes", "max_fragment_chunk",
                     "max_fragment_hole", "reserved_pin_section", "ckpt_thread_ioprio"]);
    controls.extend(["reserved_segments", "reserved_blocks", "carve_out", "peak_atomic_write"]);
    // The fourth owner is the placement pair: the armed in-place-update set and
    // the three thresholds its arms compare against.
    controls.extend(["ipu_policy", "min_ipu_util", "min_fsync_blocks", "min_ssr_sections"]);
    // The injection record is the third owner: its fields are written one at a
    // time, and every injection site consults them.
    controls.extend(["inject_rate", "inject_type", "inject_lock_timeout"]);
    // The extension lists are the fifth: the write reaches the SUPERBLOCK, so
    // a name added here is seen by every later mount.
    controls.push("extension_list");
    for a in mount_attrs(&fs).iter().chain(global_attrs().iter()) {
        let control = controls.contains(&a.name);
        assert_eq!(a.store.is_some(), control, "{}/{}", a.dir, a.name);
        assert_eq!(a.mode, if control { crate::fsattr::RW } else { crate::fsattr::RO },
                   "{}/{}", a.dir, a.name);
    }
}

/// A control is only a control if the value reaches the thread that reads it.
#[test]
fn a_written_control_reaches_the_machinery_and_reads_back() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let a = attrs.iter().find(|a| a.name == "discard_granularity").expect("published");
    let store = a.store.as_ref().expect("writable");
    assert_eq!(store(b"64\n").expect("accepted"), 3, "the whole write was consumed");
    assert_eq!(fs.bg().dcc.lock().granularity, 64, "the discard thread reads this");
    assert_eq!((a.show)().unwrap(), b"64\n");
    assert!(store(b"0\n").is_err(), "zero is not a granularity");
    assert_eq!(fs.bg().dcc.lock().granularity, 64, "and a refusal changed nothing");
}

#[test]
fn idle_threshold_controls_are_live_and_wake_both_consumers() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    fs.bg().gc.lock().gc_wake = false;
    fs.bg().dcc.lock().wake = false;
    for name in ["idle_interval", "discard_idle_interval", "gc_idle_interval"] {
        let a = attrs.iter().find(|a| a.name == name).expect("published");
        a.store.as_ref().unwrap()(b"17\n").expect("accepted");
        assert_eq!((a.show)().unwrap(), b"17\n");
    }
    assert!(fs.bg().gc.lock().gc_wake);
    assert!(fs.bg().dcc.lock().wake);
    assert_eq!(fs.bg().idle_interval(crate::bg::gc::IdleKind::Gc), 17);
    assert_eq!(fs.bg().idle_interval(crate::bg::gc::IdleKind::Discard), 17);
}

/// Setting the urgent mode through sysfs must actually start the cleaner,
/// which is the only reason a tool writes it.
#[test]
fn the_urgency_control_asks_the_cleaner_for_a_pass() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let a = attrs.iter().find(|a| a.name == "gc_urgent").expect("published");
    a.store.as_ref().unwrap()(b"1").expect("accepted");
    assert_eq!(fs.bg().gc_mode(), crate::bg::GcMode::UrgentHigh);
    assert!(fs.bg().gc.lock().gc_wake);
}

#[test]
fn checkpoint_thread_priority_is_live_and_linux_shaped() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let a = attrs.iter().find(|a| a.name == "ckpt_thread_ioprio").expect("published");
    assert_eq!((a.show)().unwrap(), b"rt,3\n");
    a.store.as_ref().unwrap()(b"be,6\n").expect("accepted");
    assert_eq!((a.show)().unwrap(), b"be,6\n");
    assert!(a.store.as_ref().unwrap()(b"rt,8").is_err());
    assert_eq!((a.show)().unwrap(), b"be,6\n");
}

/// The layout attributes must report the volume's real geometry, not a
/// constant: the fixture's main area does not begin at zero.
#[test]
fn layout_attributes_report_the_volumes_own_numbers() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let main = fs.volume.lock().super_block().main_blkaddr;
    assert_eq!(show(&attrs, "vda", "main_blkaddr"), alloc::format!("{main}\n"));
    assert_ne!(main, 0, "the fixture's main area is not at block zero");
}

/// A segment count must be read off the segment TABLE. A mount that has not
/// written has never had reason to load it, and a count taken from the empty
/// table reports every segment free — a volume with nothing on it, which is
/// not what a volume holding a root directory looks like.
#[test]
fn segment_counts_come_from_the_segment_table() {
    for writable in [true, false] {
        let fs = mounted_rw("/dev/vda", writable);
        let attrs = mount_attrs(&fs);
        let total = fs.volume.lock().super_block().segment_count_main;
        let free: u32 = show(&attrs, "vda", "free_segments").trim().parse().expect("number");
        let dirty: u32 = show(&attrs, "vda", "dirty_segments").trim().parse().expect("number");
        assert!(free > 0, "a fresh fixture has free segments");
        assert!(free + dirty <= total);
        assert!(free < total,
            "writable={writable}: the fixture's root occupies a segment, so not every \
             segment can be free");
    }
}

/// `cp_status` is the checkpoint's own flag word, in hexadecimal with no
/// prefix — the shape a reader decodes.
#[test]
fn cp_status_is_the_checkpoints_flag_word_in_hex() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let flags = fs.volume.lock().checkpoint().flags;
    assert_eq!(show(&attrs, "vda/stat", "cp_status"), alloc::format!("{flags:x}\n"));
}

/// The in-memory status word raises a bit per condition, at the bit position
/// a reader decodes it by — composed in ONE place, so there is one word to
/// test rather than one per surface.
#[test]
fn the_status_word_raises_one_bit_per_live_condition() {
    use crate::sbflags::{bits, Derived, SbFlags};
    let none = Derived::default();
    assert_eq!(SbFlags::new().word(none), 0);
    assert_eq!(SbFlags::new().word(Derived { dirty: true, ..none }), 1 << bits::IS_DIRTY);
    assert_eq!(SbFlags::new().word(Derived { recovering: true, ..none }),
               1 << bits::POR_DOING);
    assert_eq!(SbFlags::new().word(Derived { quota_dirty: true, ..none }),
               1 << bits::QUOTA_NEED_FLUSH);
    let mut f = SbFlags::at_mount(crate::flags::CP_FSCK_FLAG);
    assert_eq!(f.word(none), 1 << bits::NEED_FSCK);
    f.disable_checkpoint(false);
    f.recovered();
    f.set_closing(true);
    assert_eq!(f.word(Derived { dirty: true, recovering: true, quota_dirty: true }),
               (1 << bits::IS_DIRTY) | (1 << bits::IS_CLOSE) | (1 << bits::NEED_FSCK)
               | (1 << bits::POR_DOING) | (1 << bits::IS_RECOVERED)
               | (1 << bits::CP_DISABLED) | (1 << bits::QUOTA_NEED_FLUSH));
    f.set_closing(false);
    assert_eq!(f.word(none) & (1 << bits::IS_CLOSE), 0);
    // The latch is not lowered by anything: what this mount put back stays
    // said.
    assert_ne!(f.word(none) & (1 << bits::IS_RECOVERED), 0);
}

/// An ordinary read-write mount does NOT raise the "writable" bit.
///
/// The bit does not mean "this mount can be written to". It marks the window
/// in which a READ-ONLY mount has been made writable transiently so it can
/// repair itself, and it is cleared again as soon as that window closes. This
/// test previously asserted the opposite and passed, because the bit was fed
/// from `writable()` — so a monitoring tool reading it was told the inverse of
/// what it means, on every mount.
#[test]
fn sb_status_does_not_call_an_ordinary_mount_transiently_writable() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let word = u64::from_str_radix(show(&attrs, "vda/stat", "sb_status").trim(), 16)
        .expect("hex");
    assert!(fs.is_writable(), "the fixture is a read-write mount");
    assert!(word & (1 << 15) == 0,
            "an ordinary read-write mount is not in a transient-writable window");
}

/// `feature_list` answers about the VOLUME, so a bit the volume does not
/// carry reads `unsupported` even when this build implements it.
#[test]
fn feature_list_answers_about_the_volume_not_the_build() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let feature = fs.volume.lock().super_block().feature;
    for (bit, name) in super::feature_list::listed() {
        let want = if feature & bit != 0 { "supported\n" } else { "unsupported\n" };
        assert_eq!(show(&attrs, "vda/feature_list", name), want, "{name}");
    }
    // The fixture is not formatted for device aliasing, and this build would
    // refuse it anyway — the entry must still exist and say so.
    assert_eq!(show(&attrs, "vda/feature_list", "device_alias"), "unsupported\n");
}

/// The comma-separated `features` line and `feature_list/` are two renderings
/// of ONE feature word; a name in one and not the other means they disagree.
#[test]
fn the_features_line_agrees_with_the_feature_list_directory() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let line = show(&attrs, "vda", "features");
    let listed: Vec<&str> = line.trim().split(", ").filter(|s| !s.is_empty()).collect();
    for (_, name) in super::feature_list::listed() {
        let supported = show(&attrs, "vda/feature_list", name) == "supported\n";
        assert_eq!(supported, listed.contains(name), "{name}");
    }
}

/// A volume with no case folding says so rather than naming a version it does
/// not have.
#[test]
fn encoding_reports_none_when_the_volume_does_not_fold() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    assert_eq!(show(&attrs, "vda", "encoding"), "(none)\n");
    assert_eq!(show(&attrs, "vda", "encoding_flags"), "0\n");
}

/// The effective mode resolves `auto`, which is the whole point of the
/// attribute: `auto` on its own does not tell a reader which pass runs.
#[test]
fn the_effective_lookup_mode_resolves_auto() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let mode = show(&attrs, "vda", "effective_lookup_mode");
    assert!(mode == "auto:compat\n" || mode == "auto:perf\n" || mode == "perf\n"
            || mode == "compat\n", "unexpected {mode:?}");
}

/// The extension list is two labelled sections, even when the volume carries
/// no extensions — a reader parses the labels.
#[test]
fn the_extension_list_carries_both_sections() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let body = show(&attrs, "vda", "extension_list");
    assert!(body.starts_with("cold file extension:\n"));
    assert!(body.contains("hot file extension:\n"));
}

/// A fresh mount has announced nothing, so both discard counts are zero —
/// and they count different things, which is why both exist.
#[test]
fn discard_counts_start_empty_and_count_runs_and_blocks_separately() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    assert_eq!(show(&attrs, "vda", "pending_discard"), "0\n");
    assert_eq!(show(&attrs, "vda/stat", "undiscard_blks"), "0\n");

    // Both come off the DISCARD CONTROL, which is the one owner of what is
    // outstanding. A block released since the last checkpoint is not outstanding
    // — that checkpoint may make it live again — so parking one on the volume's
    // own list must move neither figure.
    fs.volume.lock().pending_discard.extend_from_slice(&[100, 101, 102, 200]);
    assert_eq!(show(&attrs, "vda", "pending_discard"), "0\n");
    assert_eq!(show(&attrs, "vda/stat", "undiscard_blks"), "0\n");

    fs.bg().dcc.lock().extend([(100u32, 3u32), (200, 1)]);

    assert_eq!(show(&attrs, "vda", "pending_discard"), "2\n", "two runs");
    assert_eq!(show(&attrs, "vda/stat", "undiscard_blks"), "4\n", "four blocks");
    // In flight is a third state, and nothing has been handed over yet.
    assert_eq!(show(&attrs, "vda/stat", "queued_discard"), "0\n");
}

/// Every attribute must render off the LIVE volume: a value captured when the
/// attribute set was built would never move.
#[test]
fn an_attribute_reflects_a_change_made_after_it_was_published() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let before = show(&attrs, "vda/stat", "sb_status");
    fs.volume.lock().dirty = true;
    let after = show(&attrs, "vda/stat", "sb_status");
    assert_ne!(before, after, "sb_status did not follow the volume");
    let word = u64::from_str_radix(after.trim(), 16).expect("hex");
    assert!(word & 1 != 0, "the dirty bit did not rise");
}

/// The extension list takes a write, and the write reaches the MEDIUM.
///
/// The read-back is through a fresh mount of the bytes the volume left behind,
/// because an attribute that changed only memory would satisfy any assertion
/// made through the mount that took the write.
#[test]
fn an_extension_written_through_sysfs_is_on_the_medium() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let a = attrs.iter().find(|a| a.dir == "vda" && a.name == "extension_list").expect("published");
    let store = a.store.as_ref().expect("writable");
    assert_eq!(store(b"[h]qcow2\n").expect("accepted"), 9, "the whole write was consumed");
    let shown = String::from_utf8((a.show)().unwrap()).unwrap();
    let (cold, hot) = shown.split_once("hot file extension:\n").expect("both lists");
    assert!(hot.contains("qcow2\n"), "{shown}");
    assert!(!cold.contains("qcow2\n"), "the name landed in the wrong list: {shown}");

    // Refusals, and that a refusal changes nothing.
    assert!(store(b"[h]qcow2\n").is_err(), "a name already listed was taken twice");
    assert!(store(b"qcow2\n").is_err(), "a line naming no list was accepted");
    assert!(store(b"[c]!nosuchext\n").is_err(), "a name in no list was removed");
    assert_eq!(String::from_utf8((a.show)().unwrap()).unwrap(), shown);

    // That the change reaches the MEDIUM is pinned by
    // `volume::extlist::tests`, which remounts the bytes; what is pinned here is
    // that the file's write reaches the volume that writes them. The mount's own
    // parsed superblock is re-read from the committed copy by `adopt_super`.
    let sb = fs.volume.lock().super_block().clone();
    let hot_names: alloc::vec::Vec<&str> = sb.extensions.iter()
        .skip(sb.extension_count as usize).take(sb.hot_ext_count as usize)
        .map(|s| s.as_str()).collect();
    assert!(hot_names.contains(&"qcow2"), "the write did not reach the volume: {hot_names:?}");

    assert_eq!(store(b"[h]!qcow2\n").expect("accepted"), 10);
    assert_eq!(fs.volume.lock().super_block().hot_ext_count, 0, "the removal did not reach it");
}
