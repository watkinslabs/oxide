//! Font resources, font files and the font directory record.
use super::{put, put16, read};
use super::super::native::font_height::{table, word};
use super::super::registry;
use syscall::nt_native_gdi as abi;
use windows_gdi::RasterFont;

const FILE_INFO_FIXED: usize = abi::FILE_INFO_BYTES as usize;
const FONT_DIR: usize = abi::FONT_DIR_BYTES as usize;
/// Offset of the face-name area inside the font directory record.
const FONT_DIR_FACE: usize = 118;
const FONT_DIR_COPYRIGHT: &[u8] = b"Wine fontdir";
const FONT_DIR_VERSION: u16 = 0x200;
const FONT_DIR_SIZE: u32 = 149;
const FONT_DIR_TYPE: u16 = 0x4003;
const FONT_DIR_EMBED: u16 = 0x80;
const FONT_DIR_RESOLUTION: u16 = 72;
const FONT_DIR_FACE_UNITS: usize = 32;
/// The realization height the reference measures a font directory at.
const FONT_DIR_HEIGHT: i32 = 100;
const TMPF_TRUETYPE: u8 = 0x04;
/// A private font resource is not shared with other processes.
const FR_PRIVATE: u32 = 0x10;
const MAX_FONT_BYTES: u64 = 16 * 1024 * 1024;
/// Font names without a path component are resolved against this directory.
const SYSTEM_FONT_DIRECTORY: &str = "/usr/share/fonts";

pub(super) fn execute(request: &abi::QueryRequest, input: &[u16]) -> Option<(u32, Vec<u8>)> {
    match request.kind {
        abi::QUERY_FONT_FILE_DATA => file_data(request),
        abi::QUERY_FONT_FILE_INFO => file_info(request),
        abi::QUERY_MAKE_FONT_DIR => font_dir(request, input),
        abi::QUERY_ADD_FONT_RESOURCE => Some((add(input, request.flags)?, Vec::new())),
        abi::QUERY_REMOVE_FONT_RESOURCE => Some((u32::from(remove(input)), Vec::new())),
        abi::QUERY_ADD_MEM_FONT => memory(request),
        abi::QUERY_REMOVE_MEM_FONT => Some((u32::from(registry::uninstall_memory(request.value as u32)), Vec::new())),
        _ => None,
    }
}

/// A resource name is a full path, or a bare name resolved in the font
/// directory; anything else names nothing. # C: O(name)
fn resolve(input: &[u16]) -> Option<String> {
    let units: Vec<u16> = input.iter().copied().take_while(|unit| *unit != 0).collect();
    let name = String::from_utf16(&units).ok()?;
    if name.starts_with('\\') || name.starts_with('/') { return Some(name.replace('\\', "/")); }
    if name.contains('\\') || name.contains('/') { return None; }
    Some(format!("{SYSTEM_FONT_DIRECTORY}/{name}"))
}

fn load(path: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_FONT_BYTES + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= MAX_FONT_BYTES && table(&bytes, b"head").is_some()).then_some(bytes)
}

/// Weight and slant of a face as its own selection record states them. # C: O(1)
fn style(bytes: &[u8]) -> Option<(i32, bool)> {
    let os2 = table(bytes, b"OS/2")?;
    Some((i32::from(word(os2, 4)?), word(os2, 62)? & 1 != 0))
}

fn add(input: &[u16], flags: u32) -> Option<u32> {
    let _ = flags & FR_PRIVATE;
    let path = resolve(input)?;
    let bytes = load(&path)?;
    let (weight, italic) = style(&bytes)?;
    registry::install(bytes, &path, weight, italic, 0).map(|_| 1)
}

fn remove(input: &[u16]) -> bool {
    resolve(input).is_some_and(|path| registry::uninstall_path(&path))
}

/// Install a face from caller memory; the caller's own address space holds
/// the resource for the duration of this synchronous call. # C: O(size)
fn memory(request: &abi::QueryRequest) -> Option<(u32, Vec<u8>)> {
    // SAFETY: the request names a caller buffer in this process, validated for
    // length by the kernel before the callback and read only while it runs.
    let bytes = unsafe { std::slice::from_raw_parts(request.value as *const u8, request.capacity as usize) }.to_vec();
    let (weight, italic) = style(&bytes)?;
    let token = registry::next_realization();
    registry::install(bytes, "", weight, italic, token)?;
    Some((token, 1u32.to_le_bytes().to_vec()))
}

fn file_data(request: &abi::QueryRequest) -> Option<(u32, Vec<u8>)> {
    let face = registry::face(request.first)?;
    let size = u64::try_from(face.bytes.len()).ok()?;
    let wanted = u64::from(request.capacity);
    if size < wanted || request.value > size - wanted { return Some((0, Vec::new())); }
    let start = usize::try_from(request.value).ok()?;
    Some((1, face.bytes.get(start..start + request.capacity as usize)?.to_vec()))
}

fn file_info(request: &abi::QueryRequest) -> Option<(u32, Vec<u8>)> {
    let face = registry::face(request.first)?;
    let units: Vec<u16> = face.path.iter().copied().take_while(|unit| *unit != 0).collect();
    let required = u32::try_from(FILE_INFO_FIXED + units.len() * 2).ok()?;
    let mut data = u64::from(required).to_le_bytes().to_vec();
    if required > request.capacity { return Some((0, data)); }
    let mut info = vec![0u8; required as usize];
    info[..8].copy_from_slice(&face.writetime.to_le_bytes());
    info[8..16].copy_from_slice(&(face.bytes.len() as u64).to_le_bytes());
    for (index, unit) in units.iter().enumerate() { put16(&mut info, 16 + index * 2, *unit); }
    data.extend_from_slice(&info);
    Some((1, data))
}

/// The font directory record of a font file, with the ANSI family, face and
/// style names appended after its fixed part. # C: O(font)
fn font_dir(request: &abi::QueryRequest, input: &[u16]) -> Option<(u32, Vec<u8>)> {
    if input.len() != request.count as usize || input.last() != Some(&0) { return Some((0, Vec::new())); }
    if input[..input.len() - 1].contains(&0) { return Some((0, Vec::new())); }
    let Some(path) = resolve(input) else { return Some((0, Vec::new())); };
    let Some(bytes) = load(&path) else { return Some((0, Vec::new())); };
    let em = word(table(&bytes, b"head")?, 18)? as i32;
    let size = super::super::native::font_height::pixel_size(&bytes, FONT_DIR_HEIGHT)?;
    let Ok(font) = RasterFont::from_bytes(&bytes, size) else { return Some((0, Vec::new())); };
    let (weight, italic) = style(&bytes)?;
    let tm = font.text_metrics_w(weight, u32::from(italic)).ok()?;
    if tm[55] & TMPF_TRUETYPE == 0 { return Some((0, Vec::new())); }
    let mut record = vec![0u8; FONT_DIR];
    put16(&mut record, 0, 1);
    put16(&mut record, 4, FONT_DIR_VERSION);
    put(&mut record, 6, FONT_DIR_SIZE as i32);
    record[10..10 + FONT_DIR_COPYRIGHT.len()].copy_from_slice(FONT_DIR_COPYRIGHT);
    put16(&mut record, 70, FONT_DIR_TYPE | if request.flags != 0 { FONT_DIR_EMBED } else { 0 });
    put16(&mut record, 72, u16::try_from(em).ok()?);
    put16(&mut record, 74, FONT_DIR_RESOLUTION);
    put16(&mut record, 76, FONT_DIR_RESOLUTION);
    put16(&mut record, 78, read(&tm, 4)? as u16);
    put16(&mut record, 80, read(&tm, 12)? as u16);
    put16(&mut record, 82, read(&tm, 16)? as u16);
    record[84] = tm[52];
    record[85] = tm[53];
    record[86] = tm[54];
    put16(&mut record, 87, read(&tm, 28)? as u16);
    record[89] = tm[56];
    put16(&mut record, 92, read(&tm, 0)? as u16);
    record[94] = tm[55];
    put16(&mut record, 95, read(&tm, 20)? as u16);
    put16(&mut record, 97, read(&tm, 24)? as u16);
    record[99] = tm[44];
    record[100] = tm[46];
    record[101] = tm[48];
    record[102] = tm[50];
    put(&mut record, 109, FONT_DIR_FACE as i32);
    let mut position = 0usize;
    for id in [1u16, 4, 2] {
        let name = registry::face_name(&bytes, id)?;
        for unit in name.iter().take(FONT_DIR_FACE_UNITS - 1) {
            if position + 1 >= FONT_DIR - FONT_DIR_FACE { break; }
            record[FONT_DIR_FACE + position] = if *unit < 0x80 { *unit as u8 } else { b'?' };
            position += 1;
        }
        record[FONT_DIR_FACE + position] = 0;
        position += 1;
    }
    Some((u32::try_from(FONT_DIR_FACE + position).ok()?, record))
}
