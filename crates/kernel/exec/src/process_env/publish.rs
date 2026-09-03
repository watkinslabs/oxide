//! Transactional publication of one dynamically mapped PE in the PEB lists.

use alloc::{vec, vec::Vec};
use super::{Error, NtModuleInput, API_SET_OFF, BLOCK_BYTES, LDR_OFF, MAX_MODULES, MOD_OFF, MOD_STRIDE, STR_OFF};

const LISTS: [(usize, usize); 3] = [(0x10, 0), (0x20, 0x10), (0x30, 0x20)];
const FULL_NAME_OFF: usize = 0x48;
const BASE_NAME_OFF: usize = 0x58;
const MODULE_BASE_OFF: usize = 0x30;
const MODULE_ENTRY_OFF: usize = 0x38;
const MODULE_SIZE_OFF: usize = 0x40;

/// Append a mapped module to all PEB loader orderings as one user-memory transaction.
/// # C: O(BLOCK_BYTES + MAX_MODULES)
#[cfg(target_os = "oxide-kernel")]
pub fn publish_module(peb: u64, module: &NtModuleInput<'_>) -> Result<(), Error> {
    if peb == 0 || module.base == 0 || module.full_name.is_empty() || module.base_name.is_empty() { return Err(Error::Einval); }
    let mut block = vec![0u8; BLOCK_BYTES];
    uaccess::copy_from_user(&mut block, peb).map_err(|_| Error::Einval)?;
    let base = peb;
    let (order, mut topology) = read_order(&block, base, 0)?;
    if order.len() >= MAX_MODULES { return Err(Error::Einval); }
    for (list, _) in LISTS.iter().enumerate() {
        if list != 0 && read_order(&block, base, list)?.0 != order { return Err(Error::Einval); }
    }
    for slot in &order { topology.insert_tail(*slot).map_err(|_| Error::Einval)?; }
    let slot = (0..MAX_MODULES).find(|slot| !topology.contains(*slot)).ok_or(Error::Einval)?;
    topology.insert_tail(slot).map_err(|_| Error::Einval)?;
    let full = utf16(module.full_name)?;
    let name = utf16(module.base_name)?;
    let cursor = string_cursor(&block, base, &order)?;
    let full_at = cursor;
    let base_at = full_at.checked_add(full.len()).ok_or(Error::Einval)?;
    let end = base_at.checked_add(name.len()).ok_or(Error::Einval)?;
    if end > API_SET_OFF { return Err(Error::Einval); }
    put_u64(&mut block, MOD_OFF + slot * MOD_STRIDE + MODULE_BASE_OFF, module.base);
    put_u64(&mut block, MOD_OFF + slot * MOD_STRIDE + MODULE_ENTRY_OFF, module.entry);
    put_u32(&mut block, MOD_OFF + slot * MOD_STRIDE + MODULE_SIZE_OFF, module.size);
    put_unicode(&mut block, MOD_OFF + slot * MOD_STRIDE + FULL_NAME_OFF, &full, base + full_at as u64);
    put_unicode(&mut block, MOD_OFF + slot * MOD_STRIDE + BASE_NAME_OFF, &name, base + base_at as u64);
    copy_u16(&mut block, full_at, &full);
    copy_u16(&mut block, base_at, &name);
    for (list, (head, link)) in LISTS.iter().enumerate() {
        let head_at = LDR_OFF + head;
        let links = topology.head(list).ok_or(Error::Einval)?;
        put_u64(&mut block, head_at, pointer(base, links.next, link));
        put_u64(&mut block, head_at + 8, pointer(base, links.prev, link));
        for index in 0..MAX_MODULES {
            if let Some(linkage) = topology.link(index, list) {
                let entry = MOD_OFF + index * MOD_STRIDE + link;
                put_u64(&mut block, entry, pointer(base, linkage.next, link));
                put_u64(&mut block, entry + 8, pointer(base, linkage.prev, link));
            }
        }
    }
    uaccess::copy_to_user(peb, &block).map_err(|_| Error::Einval)
}

#[cfg(target_os = "oxide-kernel")]
fn read_order(block: &[u8], base: u64, list: usize) -> Result<(Vec<usize>, pe::loader_list::LoaderList), Error> {
    let (head_offset, link) = LISTS[list];
    let head = LDR_OFF + head_offset;
    let sentinel = base.checked_add(head as u64).ok_or(Error::Einval)?;
    let mut current = get_u64(block, head);
    let mut order = Vec::new();
    while current != sentinel {
        let raw_relative = current.checked_sub(base).ok_or(Error::Einval)? as usize;
        if raw_relative < MOD_OFF + link || raw_relative >= MOD_OFF + MAX_MODULES * MOD_STRIDE + link { return Err(Error::Einval); }
        let relative = raw_relative - link;
        if (relative - MOD_OFF) % MOD_STRIDE != 0 { return Err(Error::Einval); }
        let slot = (relative - MOD_OFF) / MOD_STRIDE;
        if order.iter().any(|known| *known == slot) { return Err(Error::Einval); }
        order.push(slot);
        if order.len() > MAX_MODULES { return Err(Error::Einval); }
        current = get_u64(block, relative + link);
    }
    Ok((order, pe::loader_list::LoaderList::new(MAX_MODULES)))
}

#[cfg(target_os = "oxide-kernel")]
fn string_cursor(block: &[u8], base: u64, order: &[usize]) -> Result<usize, Error> {
    let mut cursor = STR_OFF;
    for slot in order {
        for offset in [FULL_NAME_OFF, BASE_NAME_OFF] {
            let descriptor = MOD_OFF + slot * MOD_STRIDE + offset;
            let pointer = get_u64(block, descriptor + 8);
            let start = pointer.checked_sub(base).ok_or(Error::Einval)? as usize;
            let capacity = u16::from_le_bytes(block[descriptor + 2..descriptor + 4].try_into().map_err(|_| Error::Einval)?) as usize;
            let end = start.checked_add(capacity).ok_or(Error::Einval)?;
            if start < STR_OFF || end > API_SET_OFF { return Err(Error::Einval); }
            cursor = cursor.max(end);
        }
    }
    Ok(cursor & !1)
}

#[cfg(target_os = "oxide-kernel")]
fn pointer(base: u64, slot: usize, link: &usize) -> u64 {
    if slot == MAX_MODULES { base + (LDR_OFF + LISTS.iter().find(|(_, offset)| offset == link).map(|(head, _)| *head).unwrap_or(0)) as u64 }
    else { base + (MOD_OFF + slot * MOD_STRIDE + *link) as u64 }
}

#[cfg(target_os = "oxide-kernel")]
fn utf16(value: &str) -> Result<Vec<u16>, Error> {
    if value.contains('\0') { return Err(Error::Einval); }
    let mut text: Vec<u16> = value.encode_utf16().collect();
    if text.len() >= (u16::MAX as usize / 2) { return Err(Error::Einval); }
    text.push(0);
    Ok(text)
}

#[cfg(target_os = "oxide-kernel")]
fn get_u64(block: &[u8], offset: usize) -> u64 { u64::from_le_bytes(block[offset..offset + 8].try_into().unwrap_or([0; 8])) }
#[cfg(target_os = "oxide-kernel")]
fn put_u16(block: &mut [u8], offset: usize, value: u16) { block[offset..offset + 2].copy_from_slice(&value.to_le_bytes()); }
#[cfg(target_os = "oxide-kernel")]
fn put_u32(block: &mut [u8], offset: usize, value: u32) { block[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }
#[cfg(target_os = "oxide-kernel")]
fn put_u64(block: &mut [u8], offset: usize, value: u64) { block[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }
#[cfg(target_os = "oxide-kernel")]
fn put_unicode(block: &mut [u8], offset: usize, value: &[u16], pointer: u64) {
    put_u16(block, offset, ((value.len() - 1) * 2) as u16);
    put_u16(block, offset + 2, (value.len() * 2) as u16);
    put_u64(block, offset + 8, pointer);
}
#[cfg(target_os = "oxide-kernel")]
fn copy_u16(block: &mut [u8], offset: usize, value: &[u16]) { for (index, word) in value.iter().enumerate() { put_u16(block, offset + index * 2, *word); } }
