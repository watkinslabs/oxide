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

fn modifier_key(index: u8) -> u16 { [29, 42, 56, 125, 97, 54, 100, 126][index as usize] }
fn keycode(usage: u8) -> Option<u16> { match usage {
    4..=29 => Some([30,48,46,32,18,33,34,35,23,36,37,38,50,49,24,25,16,19,31,20,22,47,17,45,21,44][(usage - 4) as usize]),
    30..=38 => Some(u16::from(usage - 30) + 2), 39 => Some(11), 40 => Some(28), 41 => Some(1), 42 => Some(14), 43 => Some(15), 44 => Some(57), 45 => Some(12), 46 => Some(13), 47 => Some(26), 48 => Some(27), 49 => Some(43), 50 => Some(43), 51 => Some(39), 52 => Some(40), 53 => Some(41), 54 => Some(51), 55 => Some(52), 56 => Some(53), 57 => Some(58), 58..=69 => Some(u16::from(usage - 58) + 59), _ => None,
} }

#[cfg(test)]
mod tests { use super::*;
    #[test] fn keyboard_tracks_modifiers_and_six_key_array() { let (state, events) = keyboard(&[0; 8], &[1, 0, 4, 0, 0, 0, 0, 0]).unwrap(); assert_eq!(events[0], Some(Event::Key { code: 29, value: 1 })); assert_eq!(events[1], Some(Event::Key { code: 30, value: 1 })); let (_, release) = keyboard(&state, &[0; 8]).unwrap(); assert_eq!(release[0], Some(Event::Key { code: 29, value: 0 })); assert_eq!(release[1], Some(Event::Key { code: 30, value: 0 })); }
    #[test] fn mouse_emits_button_and_signed_relative_motion() { let (_, events) = mouse(0, &[1, 2, 0xfe]).unwrap(); assert_eq!(events[0], Some(Event::Key { code: 272, value: 1 })); assert_eq!(events[1], Some(Event::Relative { code: 0, value: 2 })); assert_eq!(events[2], Some(Event::Relative { code: 1, value: -2 })); }
}
