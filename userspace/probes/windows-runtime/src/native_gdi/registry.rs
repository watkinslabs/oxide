//! Installed and caller-added font faces: the one source the font family
//! enumerates, realizes and reports files from.
use std::sync::{Mutex, OnceLock};
use super::native::font_height::{table, word};

/// Windows epoch offset of the Unix epoch, in 100-nanosecond units.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
const HUNDRED_NANOS_PER_SECOND: u64 = 10_000_000;
/// Face records are addressed by a realization handle that is never reused.
const FIRST_HANDLE: u32 = 1;

#[derive(Clone)]
pub(super) struct Face {
    pub handle: u32,
    pub bytes: std::sync::Arc<Vec<u8>>,
    pub path: Vec<u16>,
    pub writetime: u64,
    pub weight: i32,
    pub italic: bool,
    /// Outstanding font-resource additions; a face reaching zero is removed.
    pub refs: u32,
    /// Non-zero for a face installed from caller memory rather than a file.
    pub memory: u32,
}

impl Face {
    /// Family, full and style names as stored by the face itself. # C: O(name table)
    pub fn names(&self) -> Option<[Vec<u16>; 3]> {
        Some([self.name(1)?, self.name(4)?, self.name(2)?])
    }
    pub fn name(&self, id: u16) -> Option<Vec<u16>> { face_name(&self.bytes, id) }
}

#[derive(Default)]
pub(super) struct Registry { faces: Vec<Face>, next_handle: u32, realizations: u32 }

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| Mutex::new(Registry { faces: Vec::new(), next_handle: FIRST_HANDLE, realizations: 0 }))
}

/// Read a UTF-16 name-table string, preferring the English entry. # C: O(name table)
pub(super) fn face_name(bytes: &[u8], id: u16) -> Option<Vec<u16>> {
    let table = table(bytes, b"name")?;
    let count = word(table, 2)? as usize;
    let start = word(table, 4)? as usize;
    let entries = table.get(6..6usize.checked_add(count.checked_mul(12)?)?)?;
    let entry = entries.chunks_exact(12).filter(|e| word(e, 0) == Some(3) && word(e, 6) == Some(id))
        .max_by_key(|e| usize::from(word(e, 4) == Some(0x409)))?;
    let offset = start.checked_add(word(entry, 10)? as usize)?;
    let data = table.get(offset..offset.checked_add(word(entry, 8)? as usize)?)?;
    if data.len() % 2 != 0 { return None; }
    Some(data.chunks_exact(2).map(|unit| u16::from_be_bytes([unit[0], unit[1]])).collect())
}

fn utf16(text: &str) -> Vec<u16> { text.encode_utf16().collect() }

fn modified(path: &std::path::Path) -> u64 {
    let Ok(time) = std::fs::metadata(path).and_then(|meta| meta.modified()) else { return FILETIME_UNIX_EPOCH; };
    let seconds = time.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    FILETIME_UNIX_EPOCH + seconds.saturating_mul(HUNDRED_NANOS_PER_SECOND)
}

/// Register one face; an already-present file only takes another reference.
/// # C: O(faces)
pub(super) fn install(bytes: Vec<u8>, path: &str, weight: i32, italic: bool, memory: u32) -> Option<u32> {
    let path16 = utf16(path);
    let mut registry = registry().lock().ok()?;
    if memory == 0 {
        if let Some(face) = registry.faces.iter_mut().find(|face| face.path == path16 && face.memory == 0) {
            face.refs = face.refs.saturating_add(1);
            return Some(face.handle);
        }
    }
    let handle = registry.next_handle;
    registry.next_handle = handle.checked_add(1)?;
    registry.faces.push(Face { handle, bytes: std::sync::Arc::new(bytes), path: path16,
        writetime: modified(std::path::Path::new(path)), weight, italic, refs: 1, memory });
    Some(handle)
}

/// Drop one reference to a file-backed face; the last reference removes it. # C: O(faces)
pub(super) fn uninstall_path(path: &str) -> bool {
    let path16 = utf16(path);
    let Ok(mut registry) = registry().lock() else { return false; };
    let Some(index) = registry.faces.iter().position(|face| face.path == path16 && face.memory == 0) else { return false; };
    registry.faces[index].refs -= 1;
    if registry.faces[index].refs == 0 { registry.faces.remove(index); }
    true
}

/// Drop a memory face by the handle its installation returned. # C: O(faces)
pub(super) fn uninstall_memory(handle: u32) -> bool {
    let Ok(mut registry) = registry().lock() else { return false; };
    if let Some(index) = registry.faces.iter().position(|face| face.memory == handle && handle != 0) {
        registry.faces.remove(index);
    }
    true
}

/// Every registered face, in installation order. # C: O(faces)
pub(super) fn faces() -> Vec<Face> {
    registry().lock().map(|registry| registry.faces.clone()).unwrap_or_default()
}

/// The registered face for one realization handle. # C: O(faces)
pub(super) fn face(handle: u32) -> Option<Face> {
    registry().lock().ok()?.faces.iter().find(|face| face.handle == handle).cloned()
}

/// The face a weight and slant realize onto in this installed set. # C: O(faces)
pub(super) fn realized(weight: i32, italic: u32) -> Option<Face> {
    let bold = weight >= 600;
    let italic = italic != 0;
    let registry = registry().lock().ok()?;
    registry.faces.iter().find(|face| face.memory == 0 && (face.weight >= 600) == bold && face.italic == italic).cloned()
}

/// A realization counter that only ever increases, as the caller observes. # C: O(1)
pub(super) fn next_realization() -> u32 {
    let Ok(mut registry) = registry().lock() else { return 0; };
    registry.realizations = registry.realizations.saturating_add(1);
    registry.realizations
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
