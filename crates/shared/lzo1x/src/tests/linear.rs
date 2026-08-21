extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::decode::decompress;
use crate::encode::{compress_counted, Workspace};

const CHUNK: usize = 32 * 4096;

fn pfn_bytes() -> Vec<u8> {
    let mut input = Vec::with_capacity(CHUNK);
    for pfn in 0..CHUNK / 8 { input.extend_from_slice(&(pfn as u64).to_le_bytes()); }
    input
}

fn hash_collision_bytes() -> Vec<u8> {
    let mut input = Vec::with_capacity(CHUNK);
    for index in 0..CHUNK / 4 {
        input.extend_from_slice(&[0x53, 0x41, 0x4d, index as u8]);
    }
    input
}

fn noise_bytes() -> Vec<u8> {
    let mut input = vec![0u8; CHUNK];
    let mut state = 0x9e37_79b9u32;
    for byte in &mut input {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        *byte = state as u8;
    }
    input
}

fn prove_linear_roundtrip(input: &[u8], workspace: &mut Workspace) {
    let mut encoded = vec![0u8; input.len() + input.len() / 16 + 67];
    let (written, probes) = compress_counted(input, &mut encoded, false, workspace).unwrap();
    assert!(probes <= input.len(), "one direct dictionary probe per visited input position");
    let mut decoded = vec![0u8; input.len()];
    assert_eq!(decompress(&encoded[..written], &mut decoded), Ok(input.len()));
    assert_eq!(decoded, input);
}

#[test]
fn pfn_zero_collision_and_noise_chunks_keep_linear_work() {
    let mut workspace = Workspace::new();
    for input in [pfn_bytes(), vec![0u8; CHUNK], hash_collision_bytes(), noise_bytes()] {
        prove_linear_roundtrip(&input, &mut workspace);
    }
}

#[test]
fn reusable_workspace_is_cleared_between_hostile_streams() {
    let mut workspace = Workspace::new();
    prove_linear_roundtrip(&hash_collision_bytes(), &mut workspace);
    prove_linear_roundtrip(&pfn_bytes(), &mut workspace);
}
