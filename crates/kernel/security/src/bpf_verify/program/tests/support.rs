//! Instruction and map fixtures shared by the verifier test tree.

use alloc::vec::Vec;
use vfs::InodeRef;

use crate::bpf::uapi;

/// Decode a whitespace-tolerant hex dump of a compiled program.
pub(crate) fn hex(source: &str) -> Vec<u8> {
    let compact: Vec<u8> = source.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    compact.chunks_exact(2).map(|pair| {
        let digit = |value: u8| match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("bad hex"),
        };
        digit(pair[0]) << 4 | digit(pair[1])
    }).collect()
}

/// Build a live array map for relocation fixtures.
pub(crate) fn array(value_size: u32, max_entries: u32, flags: u32) -> InodeRef {
    crate::bpf::map::allocate(
        uapi::map_type::ARRAY, 4, value_size, max_entries, flags,
    ).unwrap()
}

/// Assemble one instruction slot.
pub(crate) fn raw(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let off = off.to_le_bytes();
    let imm = imm.to_le_bytes();
    [opcode, src << 4 | dst, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
}

/// Concatenate assembled slots into a program image.
pub(crate) fn cat(parts: &[[u8; 8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.len() * 8);
    for part in parts { out.extend_from_slice(part); }
    out
}
