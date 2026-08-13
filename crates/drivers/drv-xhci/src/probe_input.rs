//! HID-to-input publication and teardown.

use crate::probe::UsbDeviceState;

fn advertise(bits: &mut [u8], code: u16) { bits[code as usize / 8] |= 1 << (code % 8); }
pub(crate) fn platform_id(bdf: pci::Bdf, slot: u8) -> u32 { crate::identity::input_platform_id(bdf, slot) }

#[inline(never)]
pub(crate) fn install_hid_input(bdf: pci::Bdf, slot: u8, layout: Option<crate::hid_report::ReportLayout>) -> Option<u32> {
    let layout = layout?;
    let mut dev = input::VirtioInputDev::empty_platform_boxed(platform_id(bdf, slot));
    for index in 0..layout.len() {
        let field = layout.field(index)?;
        match field.usage_page {
            7 => for usage in field.usage_min..=field.usage_max.min(u32::from(u8::MAX)) { if let Some(code) = crate::hid::keycode(usage as u8) { advertise(&mut dev.ev_bits, input::EV_KEY); advertise(&mut dev.key_bits.bits, code); } },
            9 => for usage in field.usage_min.max(1)..=field.usage_max.min(29) { advertise(&mut dev.ev_bits, input::EV_KEY); advertise(&mut dev.key_bits.bits, 271 + usage as u16); },
            1 if field.flags & 4 != 0 && (field.usage_min..=field.usage_max).contains(&0x30) => { dev.is_pointer = true; advertise(&mut dev.ev_bits, input::EV_REL); advertise(&mut dev.rel_bits.bits, input::REL_X); },
            1 if field.flags & 4 != 0 && (field.usage_min..=field.usage_max).contains(&0x31) => { dev.is_pointer = true; advertise(&mut dev.ev_bits, input::EV_REL); advertise(&mut dev.rel_bits.bits, input::REL_Y); },
            _ => {}
        }
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
    if let Some(evdev) = device.evdev { let _ = input::unpublish_evdev(evdev); }
    if let Some(platform) = device.input_platform { let _ = input::remove_device(input::InputDeviceKey::platform(platform)); }
}
