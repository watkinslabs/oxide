// `F_GETDELEG` / `F_SETDELEG` ABI: the `struct delegation` wire form and its
// validation. Ungated so the decisions are unit-tested — `072_fcntl.rs` is
// kernel-target-only, and a test inside it would compile out silently.

use syscall::errno::Errno;

/// fcntl command numbers for the delegation pair. Both sit in the
/// Linux-specific command range and take a POINTER argument, unlike the
/// lease pair which takes the type inline.
pub const F_GETDELEG: u64 = 1039;
pub const F_SETDELEG: u64 = 1040;

/// `struct delegation { u32 d_flags; u16 d_type; u16 __pad; }` — 8 bytes,
/// 4-byte aligned.
pub const DELEGATION_BYTES: usize = 8;
/// Alignment the user pointer must satisfy.
pub const DELEGATION_ALIGN: u64 = 4;

const D_FLAGS_OFF: usize = 0;
const D_TYPE_OFF:  usize = 4;
const D_PAD_OFF:   usize = 6;

/// A decoded delegation request. `d_flags` and the pad are validated away at
/// decode, so only the type survives into the decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Delegation { pub d_type: i32 }

/// Decode the user `struct delegation`. Every reserved field must be zero —
/// both the flags word and the pad — so a future flag cannot be silently
/// ignored by a kernel that predates it. # C: O(1)
pub fn decode_delegation(b: &[u8; DELEGATION_BYTES]) -> Result<Delegation, Errno> {
    let d_flags = u32::from_le_bytes([b[D_FLAGS_OFF], b[D_FLAGS_OFF + 1],
                                      b[D_FLAGS_OFF + 2], b[D_FLAGS_OFF + 3]]);
    let d_type = u16::from_le_bytes([b[D_TYPE_OFF], b[D_TYPE_OFF + 1]]);
    let pad = u16::from_le_bytes([b[D_PAD_OFF], b[D_PAD_OFF + 1]]);
    if d_flags != 0 || pad != 0 { return Err(Errno::Einval); }
    Ok(Delegation { d_type: d_type as i32 })
}

/// Encode the answer a get-delegation query writes back: the type only, with
/// the flags word and the pad left zero. # C: O(1)
pub fn encode_delegation(d_type: i32) -> [u8; DELEGATION_BYTES] {
    let mut out = [0u8; DELEGATION_BYTES];
    out[D_TYPE_OFF..D_TYPE_OFF + 2].copy_from_slice(&(d_type as u16).to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(d_flags: u32, d_type: u16, pad: u16) -> [u8; DELEGATION_BYTES] {
        let mut b = [0u8; DELEGATION_BYTES];
        b[0..4].copy_from_slice(&d_flags.to_le_bytes());
        b[4..6].copy_from_slice(&d_type.to_le_bytes());
        b[6..8].copy_from_slice(&pad.to_le_bytes());
        b
    }

    // The three delegation types round-trip through the wire form at the
    // documented offsets: type at byte 4, everything else zero.
    #[test]
    fn delegation_wire_layout_round_trips() {
        for ty in [0i32, 1, 2] {
            let b = encode_delegation(ty);
            assert_eq!(b[0..4], [0, 0, 0, 0], "flags word stays zero on the way out");
            assert_eq!(b[6..8], [0, 0], "pad stays zero on the way out");
            assert_eq!(decode_delegation(&b).unwrap().d_type, ty);
        }
        assert_eq!(DELEGATION_BYTES, 8, "struct delegation is 8 bytes");
    }

    // Reserved fields must be zero: a caller setting a flag this kernel does
    // not know is told EINVAL rather than having it silently dropped. Both the
    // flags word and the pad are reserved.
    #[test]
    fn reserved_fields_must_be_zero() {
        assert_eq!(decode_delegation(&wire(0, 1, 0)).unwrap().d_type, 1);
        assert_eq!(decode_delegation(&wire(1, 1, 0)), Err(Errno::Einval), "d_flags must be 0");
        assert_eq!(decode_delegation(&wire(0x8000_0000, 0, 0)), Err(Errno::Einval));
        assert_eq!(decode_delegation(&wire(0, 1, 1)), Err(Errno::Einval), "__pad must be 0");
    }

    // The type field is 16 bits on the wire and widens to the same i32 the
    // lease commands use, so an out-of-range value survives decode and is
    // rejected by the set-lease ladder rather than being truncated into a
    // valid type here.
    #[test]
    fn out_of_range_type_survives_decode() {
        assert_eq!(decode_delegation(&wire(0, 9, 0)).unwrap().d_type, 9);
        assert_eq!(decode_delegation(&wire(0, u16::MAX, 0)).unwrap().d_type, 65535);
    }

    // The command numbers are the two consecutive Linux-specific slots.
    #[test]
    fn command_numbers() {
        assert_eq!(F_GETDELEG, 1039);
        assert_eq!(F_SETDELEG, 1040);
    }
}
