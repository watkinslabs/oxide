//! Linux input proc metadata owned by the input driver.
//!
//! `/proc/bus/input/devices` is a generated view over the live virtio-input
//! registry. DRM and boot code must not fabricate input devices.

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

const PROC_INPUT_DEVICES_INO: vfs::Ino = 0x494e_5054_0000_0001;

fn push_escaped_string(out: &mut String, bytes: &[u8]) {
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x20..=0x7e => out.push(b as char),
            _ => out.push('?'),
        }
    }
}

fn push_bitmap_line(out: &mut String, name: &str, bits: &[u8]) {
    let end = bits.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(1);
    let _ = write!(out, "B: {name}=");
    for &b in bits[..end].iter().rev() {
        let _ = write!(out, "{b:02x}");
    }
    out.push('\n');
}

fn devices_body() -> Vec<u8> {
    let mut out = String::new();
    let mut devices = crate::devices_snapshot();
    devices.sort_by_key(|d| d.evdev_id);
    for dev in devices {
        let name_len = dev.name_len.min(dev.name.len());
        let serial_len = dev.serial_len.min(dev.serial.len());
        let _ = write!(
            out,
            "I: Bus={:04x} Vendor={:04x} Product={:04x} Version={:04x}\nN: Name=\"",
            dev.ids.bustype, dev.ids.vendor, dev.ids.product, dev.ids.version,
        );
        push_escaped_string(&mut out, &dev.name[..name_len]);
        let _ = write!(
            out,
            "\"\nP: Phys=virtio/input{}\nS: Sysfs=/devices/virtio-input/input{}\nU: Uniq=",
            dev.evdev_id, dev.evdev_id,
        );
        push_escaped_string(&mut out, &dev.serial[..serial_len]);
        let _ = write!(out, "\nH: Handlers=event{}\n", dev.evdev_id);
        push_bitmap_line(&mut out, "PROP", &dev.prop_bits);
        push_bitmap_line(&mut out, "EV", &dev.ev_bits);
        push_bitmap_line(&mut out, "KEY", &dev.key_bits.bits);
        push_bitmap_line(&mut out, "REL", &dev.rel_bits.bits);
        push_bitmap_line(&mut out, "ABS", &dev.abs_bits.bits);
        push_bitmap_line(&mut out, "LED", &dev.led_bits.bits);
        out.push('\n');
    }
    out.into_bytes()
}

/// Register the generated `/proc/bus/input/devices` file. The file may be
/// registered before PCI enumeration; reads reflect the current probed devices.
/// # C: O(depth)
pub fn init() {
    ::procfs::register(
        "/proc/bus/input/devices",
        ::procfs::dyn_file::make_gen_file(PROC_INPUT_DEVICES_INO, devices_body),
    );
}
