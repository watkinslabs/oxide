use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

use backlight::device::{effective_brightness, BacklightOps, Properties};
use backlight::{BacklightScale, BacklightType};
use vfs::KResult;

use super::CLASS;
use crate::virtual_class::{make_class_dir, make_virtual_dir};

/// The class registry is global; serialise the tests that populate it.
static CLASS_LOCK: Mutex<()> = Mutex::new(());

const ATTR_BUFFER_BYTES: usize = 256;
const MAX_LEVEL: i32 = 15;

struct Panel { programmed: AtomicI32 }

impl BacklightOps for Panel {
    fn update_status(&self, props: &Properties) -> KResult<()> {
        self.programmed.store(effective_brightness(props), Ordering::Relaxed);
        Ok(())
    }
    fn get_brightness(&self, _props: &Properties) -> Option<KResult<i32>> {
        Some(Ok(self.programmed.load(Ordering::Relaxed)))
    }
}

fn props() -> Properties {
    Properties {
        brightness: 5,
        max_brightness: MAX_LEVEL,
        ty: BacklightType::Firmware,
        scale: BacklightScale::NonLinear,
        ..Properties::default()
    }
}

fn read_all(inode: &vfs::InodeRef) -> Vec<u8> {
    let mut buf = [0u8; ATTR_BUFFER_BYTES];
    let read = inode.read(0, &mut buf).expect("attribute read");
    buf[..read].to_vec()
}

#[test]
fn a_registered_panel_publishes_the_class_attribute_set() {
    let _serial = CLASS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let panel = Arc::new(Panel { programmed: AtomicI32::new(5) });
    let dev = backlight::register("acpi_video0", props(), panel).expect("register");

    let link = make_class_dir(&CLASS).lookup("acpi_video0").expect("class entry");
    assert_eq!(link.readlink().expect("readlink"),
               b"../../devices/virtual/backlight/acpi_video0".to_vec());

    let node = make_virtual_dir(&CLASS).lookup("acpi_video0").expect("device dir");
    assert_eq!(read_all(&node.lookup("brightness").expect("brightness")), b"5\n".to_vec());
    assert_eq!(read_all(&node.lookup("max_brightness").expect("max")), b"15\n".to_vec());
    assert_eq!(read_all(&node.lookup("actual_brightness").expect("actual")), b"5\n".to_vec());
    assert_eq!(read_all(&node.lookup("bl_power").expect("bl_power")), b"0\n".to_vec());
    assert_eq!(read_all(&node.lookup("type").expect("type")), b"firmware\n".to_vec());
    assert_eq!(read_all(&node.lookup("scale").expect("scale")), b"non-linear\n".to_vec());
    assert_eq!(node.lookup("subsystem").expect("subsystem").readlink().expect("readlink"),
               b"../../../../class/backlight".to_vec());

    assert!(backlight::unregister(&dev));
}

#[test]
fn brightness_is_writable_and_the_read_only_attributes_are_not() {
    let _serial = CLASS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let panel = Arc::new(Panel { programmed: AtomicI32::new(5) });
    let dev = backlight::register("acpi_video1", props(), panel.clone()).expect("register");

    let node = make_virtual_dir(&CLASS).lookup("acpi_video1").expect("device dir");
    let brightness = node.lookup("brightness").expect("brightness");
    assert_eq!(brightness.perm(), Some(0o644));
    assert_eq!(node.lookup("max_brightness").expect("max").perm(), Some(0o444));
    assert_eq!(node.lookup("actual_brightness").expect("actual").perm(), Some(0o444));

    assert_eq!(brightness.write(0, b"12\n"), Ok(3));
    assert_eq!(read_all(&brightness), b"12\n".to_vec());
    assert_eq!(panel.programmed.load(Ordering::Relaxed), 12, "the write reached the panel");
    assert_eq!(read_all(&node.lookup("actual_brightness").expect("actual")), b"12\n".to_vec());

    assert!(brightness.write(0, b"99\n").is_err(), "a level past max must be refused");
    assert_eq!(read_all(&brightness), b"12\n".to_vec());

    assert!(backlight::unregister(&dev));
}

#[test]
fn blanking_through_bl_power_drives_the_panel_to_zero() {
    let _serial = CLASS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let panel = Arc::new(Panel { programmed: AtomicI32::new(5) });
    let dev = backlight::register("acpi_video2", props(), panel.clone()).expect("register");

    let node = make_virtual_dir(&CLASS).lookup("acpi_video2").expect("device dir");
    let power = node.lookup("bl_power").expect("bl_power");
    assert_eq!(power.write(0, b"4\n"), Ok(2));
    assert_eq!(panel.programmed.load(Ordering::Relaxed), 0);
    assert_eq!(read_all(&node.lookup("brightness").expect("brightness")), b"5\n".to_vec(),
               "blanking must not lose the requested level");
    assert_eq!(power.write(0, b"0\n"), Ok(2));
    assert_eq!(panel.programmed.load(Ordering::Relaxed), 5);

    assert!(backlight::unregister(&dev));
}

#[test]
fn the_uevent_attribute_reports_the_levels() {
    let _serial = CLASS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let panel = Arc::new(Panel { programmed: AtomicI32::new(5) });
    let dev = backlight::register("acpi_video3", props(), panel).expect("register");

    let node = make_virtual_dir(&CLASS).lookup("acpi_video3").expect("device dir");
    let uevent = node.lookup("uevent").expect("uevent");
    let body = String::from_utf8(read_all(&uevent)).expect("utf8");
    assert!(body.contains("BACKLIGHT_TYPE=firmware\n"), "{body}");
    assert!(body.contains("BRIGHTNESS=5\n"), "{body}");
    assert!(body.contains("MAX_BRIGHTNESS=15\n"), "{body}");
    assert_eq!(uevent.write(0, b"change\n"), Ok(7));

    assert!(backlight::unregister(&dev));
}

#[test]
fn an_unregistered_panel_leaves_no_directory_behind() {
    let _serial = CLASS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let panel = Arc::new(Panel { programmed: AtomicI32::new(5) });
    let dev = backlight::register("acpi_video4", props(), panel).expect("register");
    let node = make_virtual_dir(&CLASS).lookup("acpi_video4").expect("device dir");

    assert!(backlight::unregister(&dev));

    assert!(make_class_dir(&CLASS).lookup("acpi_video4").is_err());
    assert!(node.lookup("brightness").is_err());
}
