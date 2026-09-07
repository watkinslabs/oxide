//! Face identity and realization identity of the selected font.
use super::{put, put16};
use super::super::registry;
use syscall::nt_native_gdi as abi;

/// A realized outline face; the second bit reports that it is scalable.
const REALIZATION_FLAGS: i32 = 0x3;
const FILE_COUNT: i32 = 1;

/// The face name of the realization, truncated into the caller's buffer and
/// always NUL-terminated when anything is written. # C: O(name)
pub(super) fn text_face(bytes: &[u8], request: &abi::QueryRequest) -> Option<(u32, Vec<u8>)> {
    let name = registry::face_name(bytes, 1)?;
    let units: Vec<u16> = name.iter().copied().take_while(|unit| *unit != 0).collect();
    let length = u32::try_from(units.len() + 1).ok()?;
    if request.output == 0 { return Some((length, Vec::new())); }
    let count = request.value as i64 as i32;
    if count <= 0 { return Some((count as u32, Vec::new())); }
    let written = (count as u32).min(length);
    let mut data = Vec::with_capacity(written as usize * 2);
    for unit in units.iter().take(written as usize - 1) { data.extend_from_slice(&unit.to_le_bytes()); }
    data.extend_from_slice(&0u16.to_le_bytes());
    Some((written, data))
}

/// Realization identity: an increasing cache number and the stable handle
/// that names this face to the font-file queries. # C: O(faces)
pub(super) fn realization(request: &abi::QueryRequest) -> Option<(u32, Vec<u8>)> {
    let face = registry::realized(request.weight, request.italic)?;
    let mut data = vec![0u8; request.capacity as usize];
    put(&mut data, 0, request.capacity as i32);
    put(&mut data, 4, REALIZATION_FLAGS);
    put(&mut data, 8, registry::next_realization() as i32);
    put(&mut data, 12, face.handle as i32);
    if request.capacity == abi::REALIZATION_BYTES {
        put(&mut data, 16, FILE_COUNT);
        put16(&mut data, 20, 0);
        put16(&mut data, 22, 0);
    }
    Some((1, data))
}
