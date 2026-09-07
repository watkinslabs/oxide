//! Enumeration records built from the registered faces and their signatures.
use super::{charset, muldiv, put, put16, put_name, read};
use super::super::native::font_height::{table, word};
use super::super::registry::{self, Face};
use syscall::nt_native_gdi as abi;
use windows_gdi::RasterFont;

const ENTRY: usize = abi::ENUM_ENTRY_BYTES as usize;
const LOGFONT: usize = 4;
const FULL_NAME: usize = 96;
const STYLE_NAME: usize = 224;
const SCRIPT: usize = 288;
const METRICS: usize = 352;
const FACE_UNITS: usize = 32;
const FULL_UNITS: usize = 64;
/// The enumeration realization the reference reports every face at.
const ENUM_PPEM: i32 = 32;
const OUT_STROKE_PRECIS: u8 = 3;
const CLIP_STROKE_PRECIS: u8 = 2;
const DRAFT_QUALITY: u8 = 1;

/// Pitch and family bits the reference carries into the logical font.
const PITCH_FAMILY_MASK: u8 = 0xf1;
const TMPF_VECTOR: u8 = 0x02;
const TMPF_TRUETYPE: u8 = 0x04;
const TMPF_DEVICE: u8 = 0x08;
const TRUETYPE_FONTTYPE: u32 = 0x0004;
const DEVICE_FONTTYPE: u32 = 0x0002;
const RASTER_FONTTYPE: u32 = 0x0001;
const NTM_ITALIC: u32 = 0x0000_0001;
const NTM_BOLD: u32 = 0x0000_0020;
const NTM_REGULAR: u32 = 0x0000_0040;
const NTM_PS_OPENTYPE: u32 = 0x0002_0000;
const SIGNATURE_BYTES: usize = 24;

/// Signature of a face: four usage ranges then the two codepage masks. # C: O(1)
fn signature(bytes: &[u8]) -> Option<[u32; 6]> {
    let os2 = table(bytes, b"OS/2")?;
    let mut result = [0u32; 6];
    for (index, offset) in [42, 46, 50, 54, 78, 82].into_iter().enumerate() {
        result[index] = u32::from_be_bytes(os2.get(offset..offset + 4)?.try_into().ok()?);
    }
    Some(result)
}

fn ntm_flags(face: &Face) -> u32 {
    let mut flags = 0;
    if face.italic { flags |= NTM_ITALIC; }
    if face.weight >= 600 { flags |= NTM_BOLD; }
    if flags == 0 { flags = NTM_REGULAR; }
    if table(&face.bytes, b"CFF ").is_some() { flags |= NTM_PS_OPENTYPE; }
    flags
}

/// One enumeration record for a face realized at its own em square. # C: O(font)
fn record(face: &Face, charset: &charset::EnumCharset, oem: bool, family_override: Option<&[u16]>) -> Option<Vec<u8>> {
    let em = word(table(&face.bytes, b"head")?, 18)? as i32;
    if em <= 0 { return None; }
    let realized = RasterFont::from_bytes(&face.bytes, em as f32).ok()?;
    let tm = realized.text_metrics_w(face.weight, u32::from(face.italic)).ok()?;
    let cell_height = read(&tm, 0)?;
    let height = muldiv(ENUM_PPEM, cell_height, em);
    let scale = |value: i32| muldiv(height, value, cell_height);
    let mut entry = vec![0u8; ENTRY];
    entry[METRICS + 28..METRICS + 60].copy_from_slice(&tm[28..60]);
    let ascent = scale(read(&tm, 4)?);
    for (offset, value) in [(0, height), (4, ascent), (8, height - ascent), (12, scale(read(&tm, 12)?)),
        (16, scale(read(&tm, 16)?)), (20, scale(read(&tm, 20)?)), (24, scale(read(&tm, 24)?))] {
        put(&mut entry, METRICS + offset, value);
    }
    let charset_id = if oem { charset::OEM_CHARSET } else { charset.charset };
    entry[METRICS + 56] = charset_id as u8;
    put(&mut entry, METRICS + 60, ntm_flags(face) as i32);
    put(&mut entry, METRICS + 64, em);
    put(&mut entry, METRICS + 68, cell_height);
    put(&mut entry, METRICS + 72, word(table(&face.bytes, b"OS/2")?, 2)? as i16 as i32);
    for (index, value) in signature(&face.bytes)?.into_iter().enumerate() {
        put(&mut entry, METRICS + 76 + index * 4, value as i32);
    }
    debug_assert_eq!(METRICS + 76 + SIGNATURE_BYTES, ENTRY);
    let pitch = entry[METRICS + 55];
    let mut kind = 0;
    if pitch & TMPF_TRUETYPE != 0 { kind |= TRUETYPE_FONTTYPE; }
    if pitch & TMPF_DEVICE != 0 { kind |= DEVICE_FONTTYPE; }
    if pitch & TMPF_VECTOR == 0 { kind |= RASTER_FONTTYPE; }
    put(&mut entry, 0, kind as i32);
    put(&mut entry, LOGFONT, height);
    let average = read(&entry, METRICS + 20)?;
    put(&mut entry, LOGFONT + 4, average);
    put(&mut entry, LOGFONT + 16, read(&tm, 28)?);
    entry[LOGFONT + 20] = entry[METRICS + 52];
    entry[LOGFONT + 21] = entry[METRICS + 53];
    entry[LOGFONT + 22] = entry[METRICS + 54];
    entry[LOGFONT + 23] = charset_id as u8;
    entry[LOGFONT + 24] = OUT_STROKE_PRECIS;
    entry[LOGFONT + 25] = CLIP_STROKE_PRECIS;
    entry[LOGFONT + 26] = DRAFT_QUALITY;
    entry[LOGFONT + 27] = (pitch & PITCH_FAMILY_MASK) + 1;
    let names = face.names()?;
    put_name(&mut entry, LOGFONT + 28, FACE_UNITS, family_override.unwrap_or(&names[0]));
    put_name(&mut entry, FULL_NAME, FULL_UNITS, &names[1]);
    put_name(&mut entry, STYLE_NAME, FACE_UNITS, &names[2]);
    put16(&mut entry, SCRIPT, if oem { charset::OEM_SCRIPT } else { charset.script } as u16);
    Some(entry)
}

fn lower(unit: u16) -> u16 { if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + 32 } else { unit } }

fn matches(face: &Face, name: &[u16]) -> bool {
    let equal = |value: &[u16]| value.len() == name.len()
        && value.iter().zip(name).all(|(a, b)| lower(*a) == lower(*b));
    face.names().is_some_and(|names| equal(&names[0]) || equal(&names[1]))
}

/// Enumerate faces, writing whole records only while the caller's buffer holds
/// them, and always reporting the byte count of every face found. # C: O(faces)
pub(super) fn execute(request: &abi::QueryRequest, input: &[u16]) -> Option<(u32, Vec<u8>)> {
    let faces = registry::faces();
    let charsets = charset::list(request.first);
    let name: Vec<u16> = input.iter().copied().take_while(|unit| *unit != 0).collect();
    let capacity = (request.capacity / abi::ENUM_ENTRY_BYTES) as usize;
    let mut selected: Vec<&Face> = Vec::new();
    if name.is_empty() {
        for face in &faces {
            let family = face.names().map(|names| names[0].clone());
            if family.is_some() && selected.iter().all(|other| other.names().map(|n| n[0].clone()) != family) {
                selected.push(face);
            }
        }
    } else {
        selected.extend(faces.iter().filter(|face| matches(face, &name)));
    }
    let mut found = 0u32;
    let mut records = Vec::new();
    for face in selected {
        let mask = signature(&face.bytes)?[4];
        let oem = mask == 0;
        for charset in &charsets {
            if !oem {
                if mask & charset.mask == 0 { continue; }
                if charset.charset == charset::DEFAULT_CHARSET && mask & !charset.mask != 0 { continue; }
            }
            let Some(entry) = record(face, charset, oem, None) else { continue; };
            if request.output != 0 && (found as usize) < capacity { records.extend_from_slice(&entry); }
            found += 1;
            if oem { break; }
        }
    }
    let mut data = Vec::with_capacity(4 + records.len());
    data.extend_from_slice(&found.saturating_mul(abi::ENUM_ENTRY_BYTES).to_le_bytes());
    data.extend_from_slice(&records);
    Some((u32::from(request.output == 0 || found as usize <= capacity), data))
}
