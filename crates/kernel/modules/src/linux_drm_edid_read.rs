//! Linux-shaped custom EDID block acquisition.

use super::*;
use alloc::alloc::alloc;

const EDID_LENGTH: usize = 128;
const CTA_EXTENSION: u8 = 0x02;
const CTA_EXTENDED_TAG: u8 = 7;
const CTA_HF_EEODB: u8 = 0x78;
const EDID_HEADER: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];

type ReadBlock = unsafe extern "C" fn(*mut c_void, *mut u8, u32, usize) -> i32;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_edid_read_custom", drm_edid_read_custom as *const () as usize, false);
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum BlockStatus { Ok, ReadFail, Zero, HeaderBad, HeaderRepair, HeaderFixed, Checksum, Version }

fn checksum(block: &[u8]) -> u8 { block[..EDID_LENGTH - 1].iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)).wrapping_neg() }

fn status(block: &[u8], base: bool) -> BlockStatus {
    if base {
        let score = block[..8].iter().zip(EDID_HEADER).filter(|(got, want)| **got == *want).count();
        if score < 6 { return if block.iter().all(|byte| *byte == 0) { BlockStatus::Zero } else { BlockStatus::HeaderBad }; }
        if score < 8 { return BlockStatus::HeaderRepair; }
    }
    if checksum(block) != block[127] { return if block.iter().all(|byte| *byte == 0) { BlockStatus::Zero } else { BlockStatus::Checksum }; }
    if base && block[18] != 1 { return BlockStatus::Version; }
    BlockStatus::Ok
}

fn valid(status: BlockStatus, tag: u8) -> bool {
    matches!(status, BlockStatus::Ok | BlockStatus::HeaderFixed) || (status == BlockStatus::Checksum && tag == CTA_EXTENSION)
}

fn read_one(callback: ReadBlock, context: *mut c_void, block: &mut [u8], number: u32) -> BlockStatus {
    let base = number == 0;
    for attempt in 0..4 {
        // SAFETY: the callback ABI receives a writable complete EDID block and its original context.
        if unsafe { callback(context, block.as_mut_ptr(), number, EDID_LENGTH) } != 0 { return BlockStatus::ReadFail; }
        let mut current = status(block, base);
        if current == BlockStatus::HeaderRepair {
            block[..8].copy_from_slice(&EDID_HEADER);
            current = if status(block, base) == BlockStatus::Ok { BlockStatus::HeaderFixed } else { status(block, base) };
        }
        if valid(current, block[0]) || (attempt == 0 && base && current == BlockStatus::Zero) { return current; }
    }
    status(block, base)
}

fn hfeeodb_extensions(first_extension: &[u8]) -> Option<usize> {
    if first_extension[0] != CTA_EXTENSION || first_extension[1] < 3 { return None; }
    let collection_end = first_extension[2] as usize;
    if !(7..=127).contains(&collection_end) { return None; }
    let header = first_extension[4];
    if header >> 5 != CTA_EXTENDED_TAG || header & 0x1f < 2 || first_extension[5] != CTA_HF_EEODB { return None; }
    Some(first_extension[6] as usize)
}

fn compact_invalid(raw: &mut Vec<u8>, blocks: usize) -> usize {
    let mut valid_blocks = 0;
    for index in 0..blocks {
        let start = index * EDID_LENGTH;
        if valid(status(&raw[start..start + EDID_LENGTH], index == 0), raw[start]) {
            if valid_blocks != index { raw.copy_within(start..start + EDID_LENGTH, valid_blocks * EDID_LENGTH); }
            valid_blocks += 1;
        }
    }
    if valid_blocks == 0 { return 0; }
    raw[126] = (valid_blocks - 1) as u8;
    raw[127] = checksum(&raw[..EDID_LENGTH]);
    raw.truncate(valid_blocks * EDID_LENGTH);
    valid_blocks
}

/// Read a complete EDID using Linux's block retry, repair, and filtering contract. # C: O(blocks)
pub(super) extern "C" fn drm_edid_read_custom(_connector: *mut c_void, callback: Option<ReadBlock>, context: *mut c_void) -> *mut c_void {
    let Some(callback) = callback else { return core::ptr::null_mut(); };
    let mut raw = Vec::new();
    if raw.try_reserve_exact(EDID_LENGTH).is_err() { return core::ptr::null_mut(); }
    raw.resize(EDID_LENGTH, 0);
    let base_status = read_one(callback, context, &mut raw[..], 0);
    if !valid(base_status, raw[0]) { return core::ptr::null_mut(); }
    let mut blocks = raw[126] as usize + 1;
    if blocks == 1 { return into_owner(raw); }
    if raw.try_reserve_exact((blocks - 1) * EDID_LENGTH).is_err() { return core::ptr::null_mut(); }
    raw.resize(blocks * EDID_LENGTH, 0);
    let mut invalid = false;
    let mut index = 1;
    while index < blocks {
        let start = index * EDID_LENGTH;
        let current = read_one(callback, context, &mut raw[start..start + EDID_LENGTH], index as u32);
        if current == BlockStatus::ReadFail { return core::ptr::null_mut(); }
        if !valid(current, raw[start]) { invalid = true; }
        if index == 1 {
            if let Some(extensions) = hfeeodb_extensions(&raw[start..start + EDID_LENGTH]) {
                let override_blocks = extensions + 1;
                if override_blocks > blocks {
                    if raw.try_reserve_exact((override_blocks - blocks) * EDID_LENGTH).is_err() { return core::ptr::null_mut(); }
                    raw.resize(override_blocks * EDID_LENGTH, 0);
                    blocks = override_blocks;
                }
            }
        }
        index += 1;
    }
    if invalid && compact_invalid(&mut raw, blocks) == 0 { return core::ptr::null_mut(); }
    into_owner(raw)
}

fn into_owner(mut raw: Vec<u8>) -> *mut c_void {
    let size = raw.len();
    let Some(layout) = Layout::array::<u8>(size).ok() else { return core::ptr::null_mut(); };
    // SAFETY: this allocation becomes the raw allocation released by drm_edid_free.
    let owned = unsafe { alloc(layout) };
    if owned.is_null() { return core::ptr::null_mut(); }
    // SAFETY: raw and owned describe equal, non-overlapping byte ranges.
    unsafe { core::ptr::copy_nonoverlapping(raw.as_ptr(), owned, size); }
    raw.clear();
    edid_owner::from_owned(owned, size)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Source { blocks: Vec<[u8; EDID_LENGTH]>, calls: [u32; 8] }
    unsafe extern "C" fn read(context: *mut c_void, dst: *mut u8, block: u32, _len: usize) -> i32 {
        let source = unsafe { &mut *context.cast::<Source>() }; source.calls[block as usize] += 1;
        let Some(bytes) = source.blocks.get(block as usize) else { return -1; };
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, EDID_LENGTH); } 0
    }
    fn base(extensions: u8) -> [u8; EDID_LENGTH] { let mut bytes = [0u8; EDID_LENGTH]; bytes[..8].copy_from_slice(&EDID_HEADER); bytes[18] = 1; bytes[126] = extensions; bytes[127] = checksum(&bytes); bytes }
    fn extension(tag: u8, valid_checksum: bool) -> [u8; EDID_LENGTH] { let mut bytes = [0u8; EDID_LENGTH]; bytes[0] = tag; bytes[127] = checksum(&bytes); if !valid_checksum { bytes[127] ^= 1; } bytes }
    #[test]
    fn custom_read_repairs_base_and_filters_invalid_extensions() {
        let mut first = base(2); first[3] = 0; first[7] = 0xff; first[127] = checksum(&first);
        let mut source = Source { blocks: alloc::vec![first, extension(CTA_EXTENSION, false), extension(0x70, false)], calls: [0; 8] };
        let owner = drm_edid_read_custom(core::ptr::null_mut(), Some(read), (&mut source as *mut Source).cast());
        assert!(!owner.is_null()); let raw = edid_owner::drm_edid_raw(owner); assert!(!raw.is_null());
        assert_eq!(unsafe { *raw.add(126) }, 1); assert_eq!(source.calls[0], 1); assert_eq!(source.calls[1], 1); assert_eq!(source.calls[2], 4); edid_owner::drm_edid_free(owner);
    }
    #[test]
    fn custom_read_honors_hf_eeodb_and_exports_abi() {
        let first = base(1); let mut cta = extension(CTA_EXTENSION, true); cta[1] = 3; cta[2] = 7; cta[4] = (CTA_EXTENDED_TAG << 5) | 2; cta[5] = CTA_HF_EEODB; cta[6] = 2; cta[127] = checksum(&cta);
        let mut source = Source { blocks: alloc::vec![first, cta, extension(0x70, true)], calls: [0; 8] };
        let owner = drm_edid_read_custom(core::ptr::null_mut(), Some(read), (&mut source as *mut Source).cast()); assert!(!owner.is_null());
        assert_eq!(unsafe { *(edid_owner::drm_edid_raw(owner)).add(126) }, 1); assert_eq!(source.calls[2], 1); edid_owner::drm_edid_free(owner); export_symbols(); assert!(crate::symtab::is_exported("drm_edid_read_custom"));
    }
}
