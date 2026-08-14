//! HID-to-input publication and teardown.

use crate::probe::UsbDeviceState;

fn advertise(bits: &mut [u8], code: u16) { bits[code as usize / 8] |= 1 << (code % 8); }
fn advertise_field(dev: &mut input::VirtioInputDev, field: crate::hid_report::InputField) {
    match field.usage_page {
        7 => for usage in field.usage_min..=field.usage_max.min(u32::from(u8::MAX)) { if let Some(code) = crate::hid::keycode(usage as u8) { advertise(&mut dev.ev_bits, input::EV_KEY); advertise(&mut dev.key_bits.bits, code); } },
        9 => for usage in field.usage_min.max(1)..=field.usage_max.min(29) { advertise(&mut dev.ev_bits, input::EV_KEY); advertise(&mut dev.key_bits.bits, 271 + usage as u16); },
        1 if field.flags & 4 != 0 && field.flags & 2 != 0 => for index in 0..usize::from(field.count) {
            match field.usage(index) {
                0x30 => { dev.is_pointer = true; advertise(&mut dev.ev_bits, input::EV_REL); advertise(&mut dev.rel_bits.bits, input::REL_X); }
                0x31 => { dev.is_pointer = true; advertise(&mut dev.ev_bits, input::EV_REL); advertise(&mut dev.rel_bits.bits, input::REL_Y); }
                0x38 => { dev.is_pointer = true; advertise(&mut dev.ev_bits, input::EV_REL); advertise(&mut dev.rel_bits.bits, input::REL_WHEEL); }
                _ => {}
            }
        },
        _ => {}
    }
}
pub(crate) fn platform_id(bdf: pci::Bdf, slot: u8) -> u32 { crate::identity::input_platform_id(bdf, slot) }

#[inline(never)]
pub(crate) fn install_hid_input(bdf: pci::Bdf, slot: u8, layout: Option<&crate::hid_report::ReportLayout>) -> Option<u32> {
    let layout = layout?;
    let mut dev = input::VirtioInputDev::empty_platform_boxed(platform_id(bdf, slot));
    for index in 0..layout.len() {
        let field = layout.field(index)?;
        advertise_field(&mut dev, field);
    }
    if dev.ev_bits.iter().all(|bits| *bits == 0) { return None; }
    let (_, evdev) = input::install(dev)?;
    input::publish_evdev(evdev).then_some(evdev)
}

pub(crate) fn publish_report(device: &mut UsbDeviceState, report: &[u8]) {
    let Some(evdev) = device.evdev else { return; };
    let Some(decoder) = device.decoder.as_mut() else { return; };
    for event in decoder.decode(report).into_iter().flatten() { match event { crate::hid::Event::Key { code, value } => { let _ = input::push_evdev_event(evdev, input::EV_KEY, code, value); }, crate::hid::Event::Relative { code, value } => { let _ = input::push_evdev_event(evdev, input::EV_REL, code, value); } } }
}

pub(crate) fn remove_hid_input(device: &UsbDeviceState) {
    if let Some(platform) = device.input_platform { let _ = input::disconnect_device(input::InputDeviceKey::platform(platform)); }
    if let Some(evdev) = device.evdev { let _ = input::unpublish_evdev(evdev); }
    if let Some(platform) = device.input_platform { let _ = input::remove_device(input::InputDeviceKey::platform(platform)); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(bits: &[u8], code: u16) -> bool { bits[code as usize / 8] & (1 << (code % 8)) != 0 }

    #[test]
    fn standard_mouse_xy_field_advertises_both_axes() {
        let report = [
            0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x09, 0x01, 0xa1, 0x00,
            0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01,
            0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05,
            0x81, 0x01, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x15, 0x81,
            0x25, 0x7f, 0x75, 0x08, 0x95, 0x02, 0x81, 0x06, 0xc0, 0xc0,
        ];
        let layout = crate::hid_report::parse_report_descriptor(&report).unwrap();
        let mut dev = input::VirtioInputDev::empty_platform_boxed(0);
        advertise_field(&mut dev, layout.field(2).unwrap());
        assert!(set(&dev.ev_bits, input::EV_REL));
        assert!(set(&dev.rel_bits.bits, input::REL_X));
        assert!(set(&dev.rel_bits.bits, input::REL_Y));
    }
}
