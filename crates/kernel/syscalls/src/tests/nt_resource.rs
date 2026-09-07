//! Resource-directory walk over a built image and over the shipped Notepad.
//!
//! The built image reproduces the measured shape of Notepad's resource tree:
//! RT_MENU carries one name, ordinal 0x201, whose language directory holds
//! many entries and NO neutral (0) entry, and every entry offset in the tree
//! is relative to the resource root rather than to its own directory.

use super::*;
use alloc::vec::Vec;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const RSRC_RVA: u32 = 0xf000;
const RT_MENU: u64 = 4;
const RT_STRING: u64 = 6;
const NOTEPAD_MENU_ID: u64 = 0x201;
const EN_US: u16 = 0x0409;
const NEUTRAL: u16 = 0x0000;

struct Image { base: u64, bytes: Vec<u8> }

impl ImageReader for Image {
    fn u16(&self, address: u64) -> Option<u16> {
        let at = address.checked_sub(self.base)? as usize;
        let raw = self.bytes.get(at..at + 2)?;
        Some(u16::from_le_bytes([raw[0], raw[1]]))
    }
    fn u32(&self, address: u64) -> Option<u32> {
        let at = address.checked_sub(self.base)? as usize;
        let raw = self.bytes.get(at..at + 4)?;
        Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }
}

/// One directory under construction: entries are (key, offset-word).
struct Builder { blob: Vec<u8> }

impl Builder {
    fn new() -> Self { Self { blob: Vec::new() } }
    fn directory(&mut self, named: u16, entries: &[(u32, u32)]) -> u32 {
        let at = self.blob.len() as u32;
        self.blob.extend_from_slice(&[0u8; 12]);
        self.blob.extend_from_slice(&named.to_le_bytes());
        self.blob.extend_from_slice(&((entries.len() as u16) - named).to_le_bytes());
        for (key, offset) in entries {
            self.blob.extend_from_slice(&key.to_le_bytes());
            self.blob.extend_from_slice(&offset.to_le_bytes());
        }
        at
    }
    fn reserve_directory(&mut self, named: u16, count: u16) -> u32 {
        let at = self.blob.len() as u32;
        self.blob.extend_from_slice(&[0u8; 12]);
        self.blob.extend_from_slice(&named.to_le_bytes());
        self.blob.extend_from_slice(&(count - named).to_le_bytes());
        self.blob.resize(self.blob.len() + count as usize * 8, 0);
        at
    }
    fn patch_entry(&mut self, directory: u32, index: u16, key: u32, offset: u32) {
        let at = directory as usize + 16 + index as usize * 8;
        self.blob[at..at + 4].copy_from_slice(&key.to_le_bytes());
        self.blob[at + 4..at + 8].copy_from_slice(&offset.to_le_bytes());
    }
    fn data_entry(&mut self, rva: u32, size: u32) -> u32 {
        let at = self.blob.len() as u32;
        self.blob.extend_from_slice(&rva.to_le_bytes());
        self.blob.extend_from_slice(&size.to_le_bytes());
        self.blob.extend_from_slice(&[0u8; 8]);
        at
    }
    fn string(&mut self, text: &str) -> u32 {
        let at = self.blob.len() as u32;
        let wide: Vec<u16> = text.encode_utf16().collect();
        self.blob.extend_from_slice(&(wide.len() as u16).to_le_bytes());
        for unit in &wide { self.blob.extend_from_slice(&unit.to_le_bytes()); }
        at
    }
}

const DIRECTORY_FLAG: u32 = 0x8000_0000;
const MENU_DATA_RVA: u32 = 0x2_7918;
const MENU_DATA_SIZE: u32 = 0x36a;
/// Language ids Notepad's menu directory carries, measured from the shipped
/// binary: ascending, no neutral entry, en-US present.
const STRING_ONLY_LANGUAGE: u16 = 0x040c;
const ABSENT_LANGUAGE: u16 = 0x0c0c;
const MEASURED_LANGUAGES: [u16; 7] = [0x0001, 0x0009, 0x000a, 0x0404, 0x0409, 0x0414, 0x0816];

fn notepad_shaped_image() -> (Image, u32) {
    let mut builder = Builder::new();
    let root = builder.reserve_directory(1, 3);
    let menu_type = builder.reserve_directory(0, 1);
    let string_type = builder.reserve_directory(0, 1);
    let named_type = builder.reserve_directory(1, 1);
    let menu_name = builder.reserve_directory(0, MEASURED_LANGUAGES.len() as u16);
    let string_name = builder.reserve_directory(0, 1);
    let named_name = builder.reserve_directory(0, 1);
    let type_string = builder.string("WEVT_TEMPLATE");
    let name_string = builder.string("MAINMENU");
    for (index, language) in MEASURED_LANGUAGES.iter().enumerate() {
        let data = builder.data_entry(MENU_DATA_RVA + index as u32, MENU_DATA_SIZE);
        builder.patch_entry(menu_name, index as u16, *language as u32, data);
    }
    let string_data = builder.data_entry(MENU_DATA_RVA, 8);
    builder.patch_entry(string_name, 0, STRING_ONLY_LANGUAGE as u32, string_data);
    let named_data = builder.data_entry(MENU_DATA_RVA, 4);
    builder.patch_entry(named_name, 0, EN_US as u32, named_data);
    builder.patch_entry(root, 0, type_string | DIRECTORY_FLAG, named_type | DIRECTORY_FLAG);
    builder.patch_entry(root, 1, RT_MENU as u32, menu_type | DIRECTORY_FLAG);
    builder.patch_entry(root, 2, RT_STRING as u32, string_type | DIRECTORY_FLAG);
    builder.patch_entry(menu_type, 0, NOTEPAD_MENU_ID as u32, menu_name | DIRECTORY_FLAG);
    builder.patch_entry(string_type, 0, 7, string_name | DIRECTORY_FLAG);
    builder.patch_entry(named_type, 0, name_string | DIRECTORY_FLAG, named_name | DIRECTORY_FLAG);
    (image_with_resources(&builder.blob), root)
}

fn image_with_resources(resources: &[u8]) -> Image {
    let mut bytes = Vec::new();
    bytes.resize(RSRC_RVA as usize, 0u8);
    bytes[0] = b'M'; bytes[1] = b'Z';
    let lfanew: u32 = 0x80;
    bytes[0x3c..0x40].copy_from_slice(&lfanew.to_le_bytes());
    let nt = lfanew as usize;
    bytes[nt..nt + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());
    let optional = nt + 24;
    bytes[optional..optional + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    let directory = optional + 112 + 2 * 8;
    bytes[directory..directory + 4].copy_from_slice(&RSRC_RVA.to_le_bytes());
    bytes[directory + 4..directory + 8].copy_from_slice(&(resources.len() as u32).to_le_bytes());
    bytes.extend_from_slice(resources);
    Image { base: IMAGE_BASE, bytes }
}

fn menu_query(language: u16) -> ResourceQuery { ResourceQuery { ty: RT_MENU, name: NOTEPAD_MENU_ID, language } }

#[test]
fn resource_root_is_the_directory_named_by_the_optional_header() {
    let (image, root) = notepad_shaped_image();
    assert_eq!(resource_root(&image, IMAGE_BASE), Some(IMAGE_BASE + RSRC_RVA as u64 + root as u64));
}

#[test]
fn neutral_request_for_the_class_menu_answers_the_english_entry() {
    let (image, _) = notepad_shaped_image();
    let root = resource_root(&image, IMAGE_BASE).unwrap();
    let entry = find_entry(&image, root, &menu_query(NEUTRAL), &ResourceLcids::baseline(), 3, false).unwrap();
    let english = MEASURED_LANGUAGES.iter().position(|language| *language == EN_US).unwrap() as u32;
    assert_eq!(image.u32(entry), Some(MENU_DATA_RVA + english));
    assert_eq!(image.u32(entry + 4), Some(MENU_DATA_SIZE));
}

#[test]
fn an_exact_language_request_answers_that_language() {
    let (image, _) = notepad_shaped_image();
    let root = resource_root(&image, IMAGE_BASE).unwrap();
    let entry = find_entry(&image, root, &menu_query(0x0414), &ResourceLcids::baseline(), 3, false).unwrap();
    let index = MEASURED_LANGUAGES.iter().position(|language| *language == 0x0414).unwrap() as u32;
    assert_eq!(image.u32(entry), Some(MENU_DATA_RVA + index));
}

#[test]
fn a_sublanguage_request_falls_back_to_its_primary_language() {
    let (image, _) = notepad_shaped_image();
    let root = resource_root(&image, IMAGE_BASE).unwrap();
    let entry = find_entry(&image, root, &menu_query(0x0809), &ResourceLcids::baseline(), 3, false).unwrap();
    let index = MEASURED_LANGUAGES.iter().position(|language| *language == 0x0009).unwrap() as u32;
    assert_eq!(image.u32(entry), Some(MENU_DATA_RVA + index));
}

#[test]
fn an_absent_explicit_language_is_not_substituted() {
    let (image, _) = notepad_shaped_image();
    let root = resource_root(&image, IMAGE_BASE).unwrap();
    let status = find_entry(&image, root, &menu_query(ABSENT_LANGUAGE), &ResourceLcids::baseline(), 3, false);
    assert_eq!(status, Err(STATUS_RESOURCE_LANG_NOT_FOUND));
}

#[test]
fn a_neutral_request_with_no_candidate_takes_the_first_entry() {
    let (image, _) = notepad_shaped_image();
    let root = resource_root(&image, IMAGE_BASE).unwrap();
    let lcids = ResourceLcids { thread: 0x0c0a, user: 0x0c0a, user_neutral: 0x000a, system: 0x0c0a };
    let query = ResourceQuery { ty: RT_STRING, name: 7, language: NEUTRAL };
    let entry = find_entry(&image, root, &query, &lcids, 3, false).unwrap();
    assert_eq!(image.u32(entry + 4), Some(8));
}

#[test]
fn levels_below_three_answer_the_directory_at_that_level() {
    let (image, _) = notepad_shaped_image();
    let root = resource_root(&image, IMAGE_BASE).unwrap();
    let type_dir = find_entry(&image, root, &menu_query(NEUTRAL), &ResourceLcids::baseline(), 1, true).unwrap();
    let name_dir = find_entry(&image, root, &menu_query(NEUTRAL), &ResourceLcids::baseline(), 2, true).unwrap();
    assert_eq!(image.u16(type_dir + 14), Some(1));
    assert_eq!(image.u16(name_dir + 14), Some(MEASURED_LANGUAGES.len() as u16));
    assert_eq!(find_entry(&image, root, &menu_query(NEUTRAL), &ResourceLcids::baseline(), 0, true), Ok(root));
}

#[test]
fn an_absent_type_and_an_absent_name_report_their_own_status() {
    let (image, _) = notepad_shaped_image();
    let root = resource_root(&image, IMAGE_BASE).unwrap();
    let absent_type = ResourceQuery { ty: 0x21, name: NOTEPAD_MENU_ID, language: NEUTRAL };
    let absent_name = ResourceQuery { ty: RT_MENU, name: 0x202, language: NEUTRAL };
    assert_eq!(find_entry(&image, root, &absent_type, &ResourceLcids::baseline(), 3, false), Err(STATUS_RESOURCE_TYPE_NOT_FOUND));
    assert_eq!(find_entry(&image, root, &absent_name, &ResourceLcids::baseline(), 3, false), Err(STATUS_RESOURCE_NAME_NOT_FOUND));
}

#[test]
fn a_string_type_and_a_string_name_are_matched_by_their_characters() {
    let (image, _) = notepad_shaped_image();
    let root = resource_root(&image, IMAGE_BASE).unwrap();
    let ty: Vec<u16> = "WEVT_TEMPLATE\0".encode_utf16().collect();
    let name: Vec<u16> = "MAINMENU\0".encode_utf16().collect();
    let miss: Vec<u16> = "MAIN\0".encode_utf16().collect();
    let key = |text: &Vec<u16>| text.as_ptr() as u64;
    let query = ResourceQuery { ty: key(&ty), name: key(&name), language: NEUTRAL };
    let reader = HostPointers { image: &image };
    let entry = find_entry(&reader, root, &query, &ResourceLcids::baseline(), 3, false).unwrap();
    assert_eq!(reader.u32(entry + 4), Some(4));
    let short = ResourceQuery { ty: key(&ty), name: key(&miss), language: NEUTRAL };
    assert_eq!(find_entry(&reader, root, &short, &ResourceLcids::baseline(), 3, false), Err(STATUS_RESOURCE_NAME_NOT_FOUND));
}

/// Reads inside the fixture image from the image, everything else from host
/// memory, so a query can carry a real UTF-16 name pointer.
struct HostPointers<'a> { image: &'a Image }

impl ImageReader for HostPointers<'_> {
    fn u16(&self, address: u64) -> Option<u16> {
        if let Some(value) = self.image.u16(address) { return Some(value); }
        // SAFETY: the address is a pointer into a caller-owned UTF-16 name
        // vector kept alive by the test that built the query.
        Some(unsafe { core::ptr::read_unaligned(address as *const u16) })
    }
    fn u32(&self, address: u64) -> Option<u32> {
        if let Some(value) = self.image.u32(address) { return Some(value); }
        // SAFETY: the address is a pointer into a caller-owned UTF-16 name
        // vector kept alive by the test that built the query.
        Some(unsafe { core::ptr::read_unaligned(address as *const u32) })
    }
}
