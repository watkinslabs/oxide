//! The damage a frame's sender measured has to survive the wire.
//!
//! A frame decoded with whole-surface damage repaints every tile of the
//! window on every paint, and one window's tile count is tens: that cost is
//! what this field exists to avoid, so a decode that loses it is a defect
//! with no other symptom than a slow desktop.
use super::*;
use crate::Rect;

/// Edge of the square surface the fixture sends.
const EDGE: u32 = 8;

fn payload(damage: wire::Damage) -> Vec<u8> {
    let mut out = Vec::new();
    for value in [EDGE, EDGE, EDGE * 4, wire::PIXEL_BGRA8888] { out.extend_from_slice(&value.to_le_bytes()); }
    out.extend_from_slice(&damage.encode());
    out.resize(wire::FRAME_HEADER_BYTES + (EDGE * EDGE * 4) as usize, 0);
    out
}

#[test]
fn a_decoded_frame_keeps_the_damage_its_sender_measured() {
    let sent = wire::Damage { left: 1, top: 2, right: 5, bottom: 6 };
    let command = decode_command(Opcode::Frame, 1, &payload(sent)).unwrap();
    let BridgeCommand::Frame { frame, .. } = command else { panic!("frame opcode decoded as another command") };
    assert_eq!(frame.damage, Rect { left: 1, top: 2, right: 5, bottom: 6 });
    assert_eq!(frame.pixels.len(), (EDGE * EDGE) as usize);
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

/// The bridge trace writes about a hundred bytes to the serial console per
/// record, inside the loop that delivers input. Off unless asked for.
#[test]
fn the_bridge_record_trace_is_off_unless_the_environment_asks_for_it() {
    assert_eq!(crate::TRACE_ENV, "OXIDE_COMPOSITOR_TRACE");
    assert!(!crate::trace_events(), "an unset environment must not trace every input record");
}
