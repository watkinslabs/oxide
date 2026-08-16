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

use super::{global_attrs, mount_attrs, mount_dir, status_word, GLOBAL_DIRS, SUBSYS};

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
    // Refused at mount, so claiming it would send a formatter into a failure.
    assert!(!listed.contains(&"block_zoned"));
    // Nothing reads the encryption bit.
    assert!(!listed.contains(&"encryption"));
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
    assert_eq!(names(&attrs, "vda/stat"), ["cp_status", "sb_status", "undiscard_blks"]);
    let fl = names(&attrs, "vda/feature_list");
    assert_eq!(fl.len(), 16, "one entry per on-disk feature bit");
    assert!(fl.contains(&"casefold"));
    assert!(fl.contains(&"device_alias"));
    assert!(!fl.contains(&"atomic_write"), "not an on-disk property");
}

/// Upstream's writable attributes all drive machinery this build lacks, so
/// nothing here accepts a write. A knob that took a value nothing reads would
/// report a change it had not made.
#[test]
fn every_published_attribute_is_read_only() {
    let fs = mounted("/dev/vda");
    for a in mount_attrs(&fs).iter().chain(global_attrs().iter()) {
        assert!(a.store.is_none(), "{}/{} accepts a write", a.dir, a.name);
        assert_eq!(a.mode, crate::fsattr::RO, "{}/{}", a.dir, a.name);
    }
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
/// a reader decodes it by.
#[test]
fn the_status_word_raises_one_bit_per_live_condition() {
    assert_eq!(status_word(false, false, false, false, 0), 0);
    assert_eq!(status_word(true, false, false, false, 0), 1 << 0);
    assert_eq!(status_word(false, false, false, false, crate::flags::CP_FSCK_FLAG), 1 << 2);
    assert_eq!(status_word(false, true, false, false, 0), 1 << 3);
    assert_eq!(status_word(false, false, false, true, 0), 1 << 8);
    assert_eq!(status_word(false, false, true, false, 0), 1 << 15);
    assert_eq!(status_word(true, true, true, true, crate::flags::CP_FSCK_FLAG),
               (1 << 0) | (1 << 2) | (1 << 3) | (1 << 8) | (1 << 15));
}

/// A writable mount says so; the bit is not decoration.
#[test]
fn sb_status_reports_the_mount_as_writable() {
    let fs = mounted("/dev/vda");
    let attrs = mount_attrs(&fs);
    let word = u64::from_str_radix(show(&attrs, "vda/stat", "sb_status").trim(), 16)
        .expect("hex");
    assert!(word & (1 << 15) != 0, "a read-write mount must raise the writable bit");
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

    fs.volume.lock().pending_discard.extend_from_slice(&[100, 101, 102, 200]);

    assert_eq!(show(&attrs, "vda", "pending_discard"), "2\n", "two runs");
    assert_eq!(show(&attrs, "vda/stat", "undiscard_blks"), "4\n", "four blocks");
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
