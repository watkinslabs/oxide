// /proc/devices — registered character + block major numbers (Linux
// `devinfo`). Character majors are a live projection of the authoritative
// driver model that also publishes devtmpfs/sysfs. Block majors come from the
// canonical block registry. The two Unix98 PTY driver registrations have no
// device-model node until open, so their always-registered majors are seeded.
#![cfg(any(target_os = "oxide-kernel", test))]

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use vfs::{Ino, InodeRef};

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

fn char_major_name(class: &'static str, name: &str, major: u32) -> &'static str {
    match (class, major) {
        ("graphics", _) => "fb",
        ("tty", 5) if name == "ptmx" => "ptmx",
        ("tty", 5) => "/dev/tty",
        ("tty", 7) => "vcs",
        ("tty", 136..=143) => "pts",
        _ => class,
    }
}

fn char_majors() -> BTreeSet<(u32, String)> {
    let mut majors = BTreeSet::new();
    // devpts registers these tty drivers before userspace. Its ptmx/slave
    // inodes are allocated outside device_add, so no model Device exists.
    majors.insert((5, String::from("ptmx")));
    majors.insert((136, String::from("pts")));
    for dev in drv::devices() {
        let Some((major, _)) = dev.dev_t else { continue };
        if dev.dev_class.is_empty() || dev.dev_class == "block" { continue; }
        let name = char_major_name(
            dev.dev_class,
            dev.devname.as_deref().unwrap_or_default(),
            major,
        );
        majors.insert((major, String::from(name)));
    }
    majors
}

fn body() -> Vec<u8> {
    use core::fmt::Write;
    let mut out: Vec<u8> = Vec::with_capacity(256);
    out.extend_from_slice(b"Character devices:\n");
    for (major, name) in char_majors() {
        let _ = writeln!(VecFmt(&mut out), "{major:>3} {name}");
    }
    out.extend_from_slice(b"\nBlock devices:\n");
    let mut seen = BTreeSet::new();
    for disk in block::registry::snapshot() {
        if seen.insert(disk.number.major) {
            let _ = writeln!(
                VecFmt(&mut out),
                "{:>3} {}",
                disk.number.major,
                disk.driver.name,
            );
        }
    }
    out
}

/// `/proc/devices` inode (KEYSTONE struct-`Inode`). # C: O(1)
pub fn make_proc_devices() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::DEVICES as Ino, body) }

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    #[test]
    fn live_device_model_majors_drive_character_device_groups() {
        let drm = drv::try_device_add(Arc::new(
            drv::Device::new(
                "proc-devices-test",
                String::from("card-b1553"),
                0,
                0,
                0,
            )
            .with_devnode(
                "drm",
                String::from("dri/card-b1553"),
                Some((226, 0)),
            ),
        ))
        .expect("publish test DRM device");
        let input = drv::try_device_add(Arc::new(
            drv::Device::new(
                "proc-devices-test",
                String::from("event-b1553"),
                0,
                0,
                0,
            )
            .with_devnode(
                "input",
                String::from("input/event-b1553"),
                Some((13, 64)),
            ),
        ))
        .expect("publish test input device");

        let text = String::from_utf8(body()).expect("ASCII /proc/devices");
        assert!(text.lines().any(|line| line.trim() == "226 drm"));
        assert!(text.lines().any(|line| line.trim() == "13 input"));

        drv::device_del(&input);
        drv::device_del(&drm);
    }
}
