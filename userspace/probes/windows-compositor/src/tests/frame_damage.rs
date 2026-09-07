//! The damage a frame's sender measured, and the pixels it carries for it,
//! have to survive the wire.
//!
//! A frame that carried the whole surface copied the window on every paint at
//! both ends of the wire, for a keystroke that changed one line of it. The
//! payload states the sub-rectangle it carries; one that states a rectangle
//! its byte count does not account for describes pixels nobody sent.
use super::*;
use crate::Rect;

/// Edge of the square surface the fixture sends.
const EDGE: u32 = 8;

fn payload(damage: wire::Damage) -> Vec<u8> {
    let row = (damage.right - damage.left).max(0) as u32;
    let rows = (damage.bottom - damage.top).max(0) as usize;
    let mut out = Vec::new();
    for value in [EDGE, EDGE, row * 4, wire::PIXEL_BGRA8888] { out.extend_from_slice(&value.to_le_bytes()); }
    out.extend_from_slice(&damage.encode());
    out.resize(wire::FRAME_HEADER_BYTES + (row as usize * rows * 4), 0);
    out
}

#[test]
fn a_decoded_frame_keeps_the_damage_its_sender_measured() {
    let sent = wire::Damage { left: 1, top: 2, right: 5, bottom: 6 };
    let command = decode_command(Opcode::Frame, 1, &payload(sent)).unwrap();
    let BridgeCommand::Frame { frame, .. } = command else { panic!("frame opcode decoded as another command") };
    assert_eq!(frame.damage, Rect { left: 1, top: 2, right: 5, bottom: 6 });
    assert_eq!((frame.width, frame.height), (EDGE, EDGE));
    assert_eq!(frame.pixels.len(), 4 * 4);
}

/// One line of a window is one line of payload. Restoring the whole surface
/// to the payload is what this refuses.
#[test]
fn a_one_line_damage_costs_one_line_of_payload_not_the_window() {
    let line = wire::Damage { left: 0, top: 3, right: EDGE as i32, bottom: 4 };
    assert_eq!(payload(line).len(), wire::FRAME_HEADER_BYTES + (EDGE * 4) as usize);
    let whole = wire::Damage { left: 0, top: 0, right: EDGE as i32, bottom: EDGE as i32 };
    assert_eq!(payload(whole).len(), wire::FRAME_HEADER_BYTES + (EDGE * EDGE * 4) as usize);
    assert!(payload(line).len() * 4 < payload(whole).len());
}

#[test]
fn damage_outside_the_surface_and_a_truncated_header_are_refused() {
    for bad in [wire::Damage { left: 0, top: 0, right: EDGE as i32 + 1, bottom: 1 },
        wire::Damage { left: -1, top: 0, right: 4, bottom: 1 },
        wire::Damage { left: 4, top: 0, right: 4, bottom: 1 }] {
        assert!(decode_command(Opcode::Frame, 1, &payload(bad)).is_err());
    }
    let mut short = payload(wire::Damage { left: 0, top: 0, right: 4, bottom: 4 });
    short.truncate(wire::FRAME_HEADER_BYTES - 1);
    assert!(decode_command(Opcode::Frame, 1, &short).is_err());
}

/// A payload sized for a different rectangle than the one it names is refused
/// at the admission boundary rather than read past or padded.
#[test]
fn a_byte_count_that_does_not_match_the_sub_rectangle_is_refused() {
    let named = wire::Damage { left: 1, top: 1, right: 5, bottom: 3 };
    let mut long = payload(named); long.extend_from_slice(&[0; 4]);
    assert!(decode_command(Opcode::Frame, 1, &long).is_err());
    let mut short = payload(named); short.truncate(short.len() - 4);
    assert!(decode_command(Opcode::Frame, 1, &short).is_err());
    // The whole surface's worth of bytes under a one-line rectangle: the
    // shape the sender used before the payload was cut to its damage.
    let mut surface = payload(wire::Damage { left: 0, top: 0, right: EDGE as i32, bottom: 1 });
    surface.resize(wire::FRAME_HEADER_BYTES + (EDGE * EDGE * 4) as usize, 0);
    assert!(decode_command(Opcode::Frame, 1, &surface).is_err());
    // A stride below the sub-rectangle's own row cannot describe it.
    let mut narrow = payload(named);
    narrow[8..12].copy_from_slice(&(3u32 * 4).to_le_bytes());
    assert!(decode_command(Opcode::Frame, 1, &narrow).is_err());
}

/// The bridge trace writes about a hundred bytes to the serial console per
/// record, inside the loop that delivers input. Off unless asked for.
#[test]
fn the_bridge_record_trace_is_off_unless_the_environment_asks_for_it() {
    assert_eq!(crate::TRACE_ENV, "OXIDE_COMPOSITOR_TRACE");
    assert!(!crate::trace_events(), "an unset environment must not trace every input record");
}
