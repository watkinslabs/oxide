//! USB HID boot-protocol report decoding, matching Linux usbkbd/usbmouse.

/// A Linux input event decoded from a boot keyboard or mouse report. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Event { Key { code: u16, value: i32 }, Relative { code: u16, value: i32 } }

/// Decode the USB HID boot keyboard eight-byte state report into key deltas. # C: O(14)
pub fn keyboard(previous: &[u8; 8], report: &[u8]) -> Option<([u8; 8], [Option<Event>; 20])> {
    let next: [u8; 8] = report.get(..8)?.try_into().ok()?;
    let mut events = [None; 20]; let mut count = 0;
    for modifier in 0..8 { if (previous[0] ^ next[0]) & (1 << modifier) != 0 { events[count] = Some(Event::Key { code: modifier_key(modifier), value: i32::from(next[0] & (1 << modifier) != 0) }); count += 1; } }
    for usage in previous[2..].iter().copied().filter(|usage| *usage > 3 && !next[2..].contains(usage)) { if let Some(code) = keycode(usage) { events[count] = Some(Event::Key { code, value: 0 }); count += 1; } }
    for usage in next[2..].iter().copied().filter(|usage| *usage > 3 && !previous[2..].contains(usage)) { if let Some(code) = keycode(usage) { events[count] = Some(Event::Key { code, value: 1 }); count += 1; } }
    Some((next, events))
}

/// Decode the standard three-byte boot mouse report. # C: O(5)
pub fn mouse(previous_buttons: u8, report: &[u8]) -> Option<(u8, [Option<Event>; 5])> {
    let buttons = *report.first()? & 0x7; let mut events = [None; 5]; let mut count = 0;
    for button in 0..3 { if (buttons ^ previous_buttons) & (1 << button) != 0 { events[count] = Some(Event::Key { code: 272 + button, value: i32::from(buttons & (1 << button) != 0) }); count += 1; } }
    if report.get(1).copied()? != 0 { events[count] = Some(Event::Relative { code: 0, value: i32::from(report[1] as i8) }); count += 1; }
    if report.get(2).copied()? != 0 { events[count] = Some(Event::Relative { code: 1, value: i32::from(report[2] as i8) }); }
    Some((buttons, events))
}

const KEYCODE: [u8; 256] = [
    0,0,0,0,30,48,46,32,18,33,34,35,23,36,37,38,50,49,24,25,16,19,31,20,22,47,17,45,21,44,2,3,
    4,5,6,7,8,9,10,11,28,1,14,15,57,12,13,26,27,43,43,39,40,41,51,52,53,58,59,60,61,62,63,64,
    65,66,67,68,87,88,99,70,119,110,102,104,111,107,109,106,105,108,103,69,98,55,74,78,96,79,
    80,81,75,76,77,71,72,73,82,83,86,127,116,117,183,184,185,186,187,188,189,190,191,192,193,194,
    134,138,130,132,128,129,131,137,133,135,136,113,115,114,0,0,0,121,0,89,93,124,92,94,95,0,
    0,0,122,123,90,91,85,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    29,42,56,125,97,54,100,126,164,166,165,163,161,115,114,113,150,158,159,128,136,177,178,176,142,152,173,140,0,0,0,0,
];

fn modifier_key(index: u8) -> u16 { KEYCODE[(index + 224) as usize] as u16 }
fn keycode(usage: u8) -> Option<u16> { u16::from(KEYCODE[usage as usize]).checked_sub(1).map(|code| code + 1) }

#[cfg(test)]
mod tests { use super::*;
    #[test] fn keyboard_tracks_modifiers_and_six_key_array() { let (state, events) = keyboard(&[0; 8], &[1, 0, 4, 0, 0, 0, 0, 0]).unwrap(); assert_eq!(events[0], Some(Event::Key { code: 29, value: 1 })); assert_eq!(events[1], Some(Event::Key { code: 30, value: 1 })); let (_, release) = keyboard(&state, &[0; 8]).unwrap(); assert_eq!(release[0], Some(Event::Key { code: 29, value: 0 })); assert_eq!(release[1], Some(Event::Key { code: 30, value: 0 })); }
    #[test] fn mouse_emits_button_and_signed_relative_motion() { let (_, events) = mouse(0, &[1, 2, 0xfe]).unwrap(); assert_eq!(events[0], Some(Event::Key { code: 272, value: 1 })); assert_eq!(events[1], Some(Event::Relative { code: 0, value: 2 })); assert_eq!(events[2], Some(Event::Relative { code: 1, value: -2 })); }
    #[test] fn keyboard_maps_keypad_navigation_and_extended_modifiers() { let (_, events) = keyboard(&[0; 8], &[0x80, 0, 89, 80, 0, 0, 0, 0]).unwrap(); assert_eq!(events[0], Some(Event::Key { code: 126, value: 1 })); assert_eq!(events[1], Some(Event::Key { code: 79, value: 1 })); assert_eq!(events[2], Some(Event::Key { code: 105, value: 1 })); }
}
