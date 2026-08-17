//! The three injection controls, written and read back through the attribute
//! surface a caller uses.
//!
//! The claim each test makes is that the value REACHES the record the injection
//! sites consult — not that it parsed. A knob that parsed and stored nowhere
//! would pass a parse test and change nothing.

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;

use crate::fault::{Fault, Timeout};
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

fn find<'a>(attrs: &'a [Attr], name: &str) -> &'a Attr {
    attrs.iter().find(|a| a.dir == "vda" && a.name == name)
        .unwrap_or_else(|| panic!("no attribute vda/{name}"))
}

fn show(attrs: &[Attr], name: &str) -> String {
    String::from_utf8((find(attrs, name).show)().expect("show")).expect("utf-8")
}

fn store(attrs: &[Attr], name: &str, body: &str) -> Result<usize, vfs::VfsError> {
    (find(attrs, name).store.as_ref().expect("writable"))(body.as_bytes())
}

#[test]
fn all_three_controls_are_writable() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    for name in ["inject_rate", "inject_type", "inject_lock_timeout"] {
        assert_eq!(find(&attrs, name).mode, crate::fsattr::RW, "{name} is read-only");
    }
}

/// The written rate reaches the record the sites consult, which is the only
/// thing that makes the control a control.
#[test]
fn a_written_rate_reaches_the_record_the_sites_consult() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    assert_eq!(show(&attrs, "inject_rate"), "0\n");
    store(&attrs, "inject_rate", "7").expect("store");
    assert_eq!(fs.volume.lock().fault_info().rate(), 7);
    assert_eq!(show(&attrs, "inject_rate"), "7\n");
}

/// A site is ARMED by the write, not merely recorded: `armed` is what the
/// injection points call.
#[test]
fn a_written_type_arms_the_site_it_names() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    let bit = Fault::Block.bit();
    assert!(!fs.volume.lock().fault_info().armed(Fault::Block));
    store(&attrs, "inject_type", &alloc::format!("{bit}")).expect("store");
    assert!(fs.volume.lock().fault_info().armed(Fault::Block),
            "the site the write named is not armed");
}

#[test]
fn a_written_timeout_kind_reaches_the_record() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    assert_eq!(fs.volume.lock().fault_info().timeout(), Timeout::None);
    let want = Timeout::IoSleep as u32;
    store(&attrs, "inject_lock_timeout", &alloc::format!("{want}")).expect("store");
    assert_eq!(fs.volume.lock().fault_info().timeout(), Timeout::IoSleep);
    assert_eq!(show(&attrs, "inject_lock_timeout"), alloc::format!("{want}\n"));
}

/// Each write carries only its own field. Setting the rate must not disarm the
/// sites, and arming a site must not clear the rate — the two are separate knobs
/// over one record, and a whole-record write would make each undo the other.
#[test]
fn one_control_does_not_reset_another() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    let bit = Fault::Block.bit();
    store(&attrs, "inject_type", &alloc::format!("{bit}")).expect("store");
    store(&attrs, "inject_rate", "5").expect("store");
    let v = fs.volume.lock();
    assert_eq!(v.fault_info().rate(), 5);
    assert!(v.fault_info().armed(Fault::Block), "setting the rate disarmed the site");
}

/// A refused value changes nothing, so a caller reads back the old value rather
/// than a half-applied pair.
#[test]
fn a_refused_timeout_kind_leaves_the_record_alone() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    let want = Timeout::Runnable as u32;
    store(&attrs, "inject_lock_timeout", &alloc::format!("{want}")).expect("store");
    assert!(store(&attrs, "inject_lock_timeout",
                  &alloc::format!("{}", crate::fault::TIMEOUT_MAX)).is_err(),
            "an index past the last kind was accepted");
    assert_eq!(fs.volume.lock().fault_info().timeout(), Timeout::Runnable);
}

#[test]
fn a_type_word_naming_a_site_this_build_has_no_point_for_is_refused() {
    let fs = mounted();
    let attrs = crate::sysfs::mount_attrs(&fs);
    let beyond = u64::from(crate::fault::ALL_TYPES) + 1;
    assert!(store(&attrs, "inject_type", &alloc::format!("{beyond}")).is_err());
    assert_eq!(fs.volume.lock().fault_info().types(), 0);
}
