//! Linux input proc metadata owned by the input driver.
//!
//! `/proc/bus/input/devices` is a generated view over the live virtio-input
//! registry. DRM and boot code must not fabricate input devices.

#![cfg(any(target_os = "oxide-kernel", test))]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

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
            "\"\nP: Phys=virtio/input{}\nS: Sysfs=/devices/virtual/input/event{}\nU: Uniq=",
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
#[cfg(target_os = "oxide-kernel")]
pub fn init() {
    ::procfs::register(
        "/proc/bus/input/devices",
        ::procfs::dyn_file::make_gen_file(crate::consts::PROC_INPUT_DEVICES_INO, devices_body),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
        virtio::VirtioChildDeviceKey::from_raw(raw)
    }

    fn test_dev(device_key: virtio::VirtioChildDeviceKey, evdev_id: u32) -> crate::VirtioInputDev {
        let mut dev = crate::VirtioInputDev {
            device_key,
            evdev_id,
            is_pointer: true,
            name: [0; 128],
            name_len: 0,
            serial: [0; 128],
            serial_len: 0,
            ids: crate::VirtioInputDevIds {
                bustype: 0x0006,
                vendor: 0x1af4,
                product: 0x1052,
                version: 0x0001,
            },
            ev_bits: [0; 32],
            key_bits: crate::CapBitmap::default(),
            rel_bits: crate::CapBitmap::default(),
            abs_bits: crate::CapBitmap::default(),
            led_bits: crate::CapBitmap::default(),
            abs_info: [None; 64],
            prop_bits: [0; 4],
            repeat: crate::DEFAULT_REPEAT,
        };
        let name = b"QEMU \"Tablet\"";
        dev.name[..name.len()].copy_from_slice(name);
        dev.name_len = name.len();
        let serial = b"seat0\\pointer";
        dev.serial[..serial.len()].copy_from_slice(serial);
        dev.serial_len = serial.len();
        dev.prop_bits[0] = 0x02;
        dev.ev_bits[(crate::EV_KEY / 8) as usize] |= 1 << (crate::EV_KEY % 8);
        dev.ev_bits[(crate::EV_REL / 8) as usize] |= 1 << (crate::EV_REL % 8);
        dev.key_bits.bits[0] = 0x01;
        dev.rel_bits.bits[0] = 0x03;
        dev
    }

    #[test]
    fn devices_body_names_virtual_input_sysfs_device() {
        crate::registry::clear_devices_for_tests();
        let device_key = key(0x1234_0000);
        crate::install(test_dev(device_key, 7));

        let body = String::from_utf8(devices_body()).expect("valid proc devices body");
        assert!(body.contains("I: Bus=0006 Vendor=1af4 Product=1052 Version=0001\n"));
        assert!(body.contains("N: Name=\"QEMU \\\"Tablet\\\"\"\n"));
        assert!(body.contains("P: Phys=virtio/input7\n"));
        assert!(body.contains("S: Sysfs=/devices/virtual/input/event7\n"));
        assert!(body.contains("U: Uniq=seat0\\\\pointer\n"));
        assert!(body.contains("H: Handlers=event7\n"));
        assert!(!body.contains("/devices/virtio-input/input"));

        assert_eq!(crate::remove_device(device_key), Some(7));
        crate::registry::clear_devices_for_tests();
    }

    #[test]
    fn devices_body_lists_multiple_input_records_in_event_order() {
        crate::registry::clear_devices_for_tests();
        let later = key(0x2000_0000);
        let first = key(0x1000_0000);
        crate::install(test_dev(later, 1));
        crate::install(test_dev(first, 0));

        let body = String::from_utf8(devices_body()).expect("valid proc devices body");
        let event0 = body.find("H: Handlers=event0\n").expect("event0 handler");
        let event1 = body.find("H: Handlers=event1\n").expect("event1 handler");
        assert!(event0 < event1);
        assert!(body.contains("P: Phys=virtio/input0\n"));
        assert!(body.contains("P: Phys=virtio/input1\n"));
        assert!(body.contains("S: Sysfs=/devices/virtual/input/event0\n"));
        assert!(body.contains("S: Sysfs=/devices/virtual/input/event1\n"));

        crate::registry::clear_devices_for_tests();
    }
}
