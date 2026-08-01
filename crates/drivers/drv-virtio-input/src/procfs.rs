//! Linux input proc metadata owned by the input driver.
//!
//! `/proc/bus/input/devices` is a generated view over the live virtio-input
//! registry. DRM and boot code must not fabricate input devices.

#![cfg(any(target_os = "oxide-kernel", test))]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

fn push_text(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(text.as_bytes());
}

fn push_bitmap_line(out: &mut Vec<u8>, name: &str, bits: &[u8]) {
    push_text(out, &alloc::format!("B: {name}={}\n", input::format_bitmap(bits)));
}

fn has_event(bits: &[u8], event_type: u16) -> bool {
    bits.get((event_type / u8::BITS as u16) as usize)
        .is_some_and(|byte| {
            byte & (1u8 << (event_type % u8::BITS as u16)) != 0
        })
}

fn event_parent_canon_exact(dev: &drv::Device) -> Option<String> {
    if dev.bus != "input" {
        return None;
    }
    let canon = drv::device_canon_exact(dev)?;
    let (parent, event) = canon.rsplit_once('/')?;
    if event != dev.addr {
        return None;
    }
    Some(String::from(parent))
}

fn devices_body() -> Vec<u8> {
    let mut out = Vec::new();
    let mut devices = crate::devices_snapshot();
    // The general sort reserves a scratch frame sized for a large input, which
    // a kernel stack cannot spare. The table is bounded by the evdev minor
    // count, so order it by walking that space instead.
    devices.sort_unstable_by_key(|d| d.evdev_id);
    for dev in devices {
        let Some(model_dev) = crate::devfs::model_device(dev.evdev_id) else {
            continue;
        };
        let Some(sysfs_parent) = event_parent_canon_exact(&model_dev) else {
            continue;
        };
        let name_len = dev.name_len.min(dev.name.len());
        let phys_len = dev.phys_len.min(dev.phys.len());
        let serial_len = dev.serial_len.min(dev.serial.len());
        push_text(
            &mut out,
            &alloc::format!(
            "I: Bus={:04x} Vendor={:04x} Product={:04x} Version={:04x}\nN: Name=\"",
            dev.ids.bustype, dev.ids.vendor, dev.ids.product, dev.ids.version,
            ),
        );
        out.extend_from_slice(&dev.name[..name_len]);
        push_text(&mut out, "\"\nP: Phys=");
        out.extend_from_slice(&dev.phys[..phys_len]);
        push_text(&mut out, &alloc::format!("\nS: Sysfs=/{sysfs_parent}\nU: Uniq="));
        out.extend_from_slice(&dev.serial[..serial_len]);
        push_text(&mut out, &alloc::format!("\nH: Handlers=event{}\n", dev.evdev_id));
        push_bitmap_line(&mut out, "PROP", &dev.prop_bits);
        push_bitmap_line(&mut out, "EV", &dev.ev_bits);
        let caps = [
            (crate::EV_KEY, "KEY", &dev.key_bits.bits[..]),
            (crate::EV_REL, "REL", &dev.rel_bits.bits[..]),
            (crate::EV_ABS, "ABS", &dev.abs_bits.bits[..]),
            (crate::EV_MSC, "MSC", &dev.msc_bits.bits[..]),
            (crate::EV_LED, "LED", &dev.led_bits.bits[..]),
            (crate::EV_SND, "SND", &dev.snd_bits.bits[..]),
            (crate::EV_FF, "FF", &dev.ff_bits.bits[..]),
            (crate::EV_SW, "SW", &dev.sw_bits.bits[..]),
        ];
        for (event_type, name, bits) in caps {
            if has_event(&dev.ev_bits, event_type) {
                push_bitmap_line(&mut out, name, bits);
            }
        }
        out.push(b'\n');
    }
    out
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

    const TEST_VENDOR: u16 = 0x1af4;
    const TEST_PRODUCT: u16 = 0x1052;
    const TEST_VERSION: u16 = 0x0001;
    const TEST_POINTER_PROP_MASK: u8 = 0x02;
    const TEST_KEY_BYTE_INDEX: usize = 3;
    const TEST_KEY_MASK: u8 = 0x40;
    const TEST_REL_MASK: u8 = 0x03;
    const VIRTUAL_DEVICE_KEY_RAW: u32 = 0x1234_0000;
    const FIRST_DEVICE_KEY_RAW: u32 = 0x1000_0000;
    const LATER_DEVICE_KEY_RAW: u32 = 0x2000_0000;
    const RAW_IDENTITY_DEVICE_KEY_RAW: u32 = 0x3000_0000;
    const TEST_PCI_DEVICE_ID: u16 = 0x1045;
    const TEST_VIRTIO_DEVICE_ID: u16 = 18;
    const RAW_NAME: [u8; 3] = [b'A', 0xff, b'B'];
    const RAW_PHYS: [u8; 3] = [b'P', 0x01, b'H'];
    const RAW_SERIAL: [u8; 3] = [b'U', b'\\', 0xfe];


    fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
        virtio::VirtioChildDeviceKey::from_raw(raw)
    }

    fn test_dev(device_key: virtio::VirtioChildDeviceKey) -> alloc::boxed::Box<crate::VirtioInputDev> {
        let mut dev = crate::VirtioInputDev::empty_boxed(device_key);
        dev.is_pointer = true;
        dev.name_present = true;
        dev.phys_present = true;
        dev.serial_present = true;
        dev.ids = crate::VirtioInputDevIds {
            bustype: crate::registry::BUS_VIRTUAL,
            vendor: TEST_VENDOR,
            product: TEST_PRODUCT,
            version: TEST_VERSION,
        };
        let name = b"QEMU \"Tablet\"";
        dev.name[..name.len()].copy_from_slice(name);
        dev.name_len = name.len();
        let phys = b"virtio7/input0";
        dev.phys[..phys.len()].copy_from_slice(phys);
        dev.phys_len = phys.len();
        let serial = b"seat0\\pointer";
        dev.serial[..serial.len()].copy_from_slice(serial);
        dev.serial_len = serial.len();
        dev.prop_bits[0] = TEST_POINTER_PROP_MASK;
        dev.ev_bits[(crate::EV_KEY / u8::BITS as u16) as usize] |=
            1 << (crate::EV_KEY % u8::BITS as u16);
        dev.ev_bits[(crate::EV_REL / u8::BITS as u16) as usize] |=
            1 << (crate::EV_REL % u8::BITS as u16);
        dev.key_bits.bits[TEST_KEY_BYTE_INDEX] = TEST_KEY_MASK;
        dev.rel_bits.bits[0] = TEST_REL_MASK;
        dev
    }

    #[test]
    fn devices_body_names_virtual_input_sysfs_device() {
        let _devices = crate::registry::own_device_table();
        crate::registry::clear_devices_for_tests();
        let device_key = key(VIRTUAL_DEVICE_KEY_RAW);
        let (input_id, evdev_id) = crate::install(test_dev(device_key))
            .expect("install proc model");
        assert!(crate::devfs::register_node(evdev_id, None));

        let body = String::from_utf8(devices_body()).expect("valid proc devices body");
        assert!(body.contains("I: Bus=0006 Vendor=1af4 Product=1052 Version=0001\n"));
        assert!(body.contains("N: Name=\"QEMU \"Tablet\"\"\n"));
        assert!(body.contains("P: Phys=virtio7/input0\n"));
        assert!(body.contains(&alloc::format!(
            "S: Sysfs=/devices/virtual/input/input{input_id}\n",
        )));
        assert!(body.contains("U: Uniq=seat0\\pointer\n"));
        assert!(body.contains(&alloc::format!("H: Handlers=event{evdev_id}\n")));
        assert!(!body.contains(&alloc::format!(
            "S: Sysfs=/devices/virtual/input/input{input_id}/event{evdev_id}\n",
        )));
        assert!(body.contains("B: KEY=40000000\n"));
        assert!(body.contains("B: REL=3\n"));
        assert!(!body.contains("B: ABS="));
        assert!(!body.contains("B: MSC="));
        assert!(!body.contains("B: LED="));
        assert!(!body.contains("B: SND="));
        assert!(!body.contains("B: FF="));
        assert!(!body.contains("B: SW="));

        assert!(crate::devfs::unregister_node(evdev_id));
        assert_eq!(crate::remove_device(device_key), Some(evdev_id));
        crate::registry::clear_devices_for_tests();
    }

    #[test]
    fn devices_body_lists_multiple_input_records_in_event_order() {
        let _devices = crate::registry::own_device_table();
        crate::registry::clear_devices_for_tests();
        let first = key(FIRST_DEVICE_KEY_RAW);
        let later = key(LATER_DEVICE_KEY_RAW);
        let (first_input, first_evdev) = crate::install(test_dev(first))
            .expect("first proc model");
        let (later_input, later_evdev) = crate::install(test_dev(later))
            .expect("later proc model");
        let pci = drv::try_device_add(alloc::sync::Arc::new(drv::Device::new(
            "pci",
            String::from("0000:00:04.0"),
            TEST_VENDOR,
            TEST_PCI_DEVICE_ID,
            0,
        ))).expect("pci parent registration");
        let virtio = drv::try_device_add(alloc::sync::Arc::new(
            drv::Device::new(
                "virtio",
                String::from("virtio1"),
                TEST_VENDOR,
                TEST_VIRTIO_DEVICE_ID,
                0,
            )
                .with_parent("pci", String::from("0000:00:04.0")),
        )).expect("virtio parent registration");
        assert!(crate::devfs::register_node(first_evdev, None));
        assert!(crate::devfs::register_node(later_evdev, Some(&virtio)));

        let body = String::from_utf8(devices_body()).expect("valid proc devices body");
        let event0 = body.find(&alloc::format!("H: Handlers=event{first_evdev}\n"))
            .expect("first handler");
        let event1 = body.find(&alloc::format!("H: Handlers=event{later_evdev}\n"))
            .expect("later handler");
        assert!(event0 < event1);
        assert!(body.contains(&alloc::format!(
            "S: Sysfs=/devices/virtual/input/input{first_input}\n",
        )));
        assert!(body.contains(&alloc::format!(
            "S: Sysfs=/devices/pci0000:00/0000:00:04.0/virtio1/input/input{later_input}\n",
        )));

        assert!(crate::devfs::unregister_node(later_evdev));
        assert!(crate::devfs::unregister_node(first_evdev));
        drv::device_del(&virtio);
        drv::device_del(&pci);
        crate::registry::clear_devices_for_tests();
    }

    #[test]
    fn devices_body_preserves_linux_raw_identity_bytes() {
        let _devices = crate::registry::own_device_table();
        crate::registry::clear_devices_for_tests();
        let device_key = key(RAW_IDENTITY_DEVICE_KEY_RAW);
        let mut model = test_dev(device_key);
        model.name[..RAW_NAME.len()].copy_from_slice(&RAW_NAME);
        model.name_len = RAW_NAME.len();
        model.phys[..RAW_PHYS.len()].copy_from_slice(&RAW_PHYS);
        model.phys_len = RAW_PHYS.len();
        model.serial[..RAW_SERIAL.len()].copy_from_slice(&RAW_SERIAL);
        model.serial_len = RAW_SERIAL.len();
        let (_, evdev_id) = crate::install(model).expect("raw identity model");
        assert!(crate::devfs::register_node(evdev_id, None));

        let body = devices_body();
        assert!(body.windows(b"N: Name=\"A\xffB\"\n".len())
            .any(|window| window == b"N: Name=\"A\xffB\"\n"));
        assert!(body.windows(b"P: Phys=P\x01H\n".len())
            .any(|window| window == b"P: Phys=P\x01H\n"));
        assert!(body.windows(b"U: Uniq=U\\\xfe\n".len())
            .any(|window| window == b"U: Uniq=U\\\xfe\n"));

        assert!(crate::devfs::unregister_node(evdev_id));
        assert_eq!(crate::remove_device(device_key), Some(evdev_id));
        crate::registry::clear_devices_for_tests();
    }
}
