//! Transactional publication of one dynamically mapped PE in the PEB lists.

use alloc::vec::Vec;
#[cfg(any(target_os = "oxide-kernel", test))]
use alloc::vec;
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
    publish_modules(peb, core::slice::from_ref(module))
}

/// Append a mapped dependency graph to every PEB loader ordering atomically.
/// # C: O(BLOCK_BYTES + N_modules * MAX_MODULES)
#[cfg(target_os = "oxide-kernel")]
pub fn publish_modules(peb: u64, modules: &[NtModuleInput<'_>]) -> Result<(), Error> {
    if peb == 0 || modules.is_empty() { return Err(Error::Einval); }
    if modules.iter().any(|module| module.base == 0 || module.full_name.is_empty() || module.base_name.is_empty()) { return Err(Error::Einval); }
    let mut block = vec![0u8; BLOCK_BYTES];
    uaccess::copy_from_user(&mut block, peb).map_err(|_| Error::Einval)?;
    for module in modules { plan(&mut block, peb, module)?; }
    uaccess::copy_to_user(peb, &block).map_err(|_| Error::Einval)
}

/// Apply one validated module publication to an in-memory PEB block.
/// # C: O(BLOCK_BYTES + MAX_MODULES)
pub fn plan(mut block: &mut [u8], base: u64, module: &NtModuleInput<'_>) -> Result<(), Error> {
    if block.len() != BLOCK_BYTES || base == 0 || module.base == 0 || module.full_name.is_empty() || module.base_name.is_empty() { return Err(Error::Einval); }
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
    Ok(())
}

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

fn pointer(base: u64, slot: usize, link: &usize) -> u64 {
    if slot == MAX_MODULES { base + (LDR_OFF + LISTS.iter().find(|(_, offset)| offset == link).map(|(head, _)| *head).unwrap_or(0)) as u64 }
    else { base + (MOD_OFF + slot * MOD_STRIDE + *link) as u64 }
}

fn utf16(value: &str) -> Result<Vec<u16>, Error> {
    if value.contains('\0') { return Err(Error::Einval); }
    let mut text: Vec<u16> = value.encode_utf16().collect();
    if text.len() >= (u16::MAX as usize / 2) { return Err(Error::Einval); }
    text.push(0);
    Ok(text)
}

fn get_u64(block: &[u8], offset: usize) -> u64 { u64::from_le_bytes(block[offset..offset + 8].try_into().unwrap_or([0; 8])) }
fn put_u16(block: &mut [u8], offset: usize, value: u16) { block[offset..offset + 2].copy_from_slice(&value.to_le_bytes()); }
fn put_u32(block: &mut [u8], offset: usize, value: u32) { block[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }
fn put_u64(block: &mut [u8], offset: usize, value: u64) { block[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }
fn put_unicode(block: &mut [u8], offset: usize, value: &[u16], pointer: u64) {
    put_u16(block, offset, ((value.len() - 1) * 2) as u16);
    put_u16(block, offset + 2, (value.len() * 2) as u16);
    put_u64(block, offset + 8, pointer);
}
fn copy_u16(block: &mut [u8], offset: usize, value: &[u16]) { for (index, word) in value.iter().enumerate() { put_u16(block, offset + index * 2, *word); } }

#[cfg(test)]
mod tests {
    use super::*;

    fn put_initial(block: &mut [u8], base: u64) {
        for (head, link) in LISTS {
            let head_at = LDR_OFF + head;
            let entry = MOD_OFF + link;
            put_u64(block, head_at, base + entry as u64);
            put_u64(block, head_at + 8, base + entry as u64);
            put_u64(block, entry, base + head_at as u64);
            put_u64(block, entry + 8, base + head_at as u64);
        }
        let full = MOD_OFF + FULL_NAME_OFF;
        let name = MOD_OFF + BASE_NAME_OFF;
        put_u16(block, full, 2);
        put_u16(block, full + 2, 4);
        put_u64(block, full + 8, base + STR_OFF as u64);
        put_u16(block, name, 2);
        put_u16(block, name + 2, 4);
        put_u64(block, name + 8, base + (STR_OFF + 4) as u64);
        copy_u16(block, STR_OFF, &[b'a' as u16, 0]);
        copy_u16(block, STR_OFF + 4, &[b'a' as u16, 0]);
        put_u64(block, MOD_OFF + MODULE_BASE_OFF, 0x1400_0000);
    }

    #[test]
    fn plan_appends_metadata_strings_and_all_three_lists() {
        let base = 0x1000_0000;
        let mut block = vec![0u8; BLOCK_BYTES];
        put_initial(&mut block, base);
        let module = NtModuleInput { base: 0x1800_0000, entry: 0x1800_1234, size: 0x5000, full_name: "C:\\Windows\\System32\\user32.dll", base_name: "user32.dll" };
        plan(&mut block, base, &module).unwrap();
        for list in 0..LISTS.len() { assert_eq!(read_order(&block, base, list).unwrap().0, vec![0, 1]); }
        let entry = MOD_OFF + MOD_STRIDE;
        assert_eq!(get_u64(&block, entry + MODULE_BASE_OFF), module.base);
        assert_eq!(get_u64(&block, entry + MODULE_ENTRY_OFF), module.entry);
        assert_eq!(u32::from_le_bytes(block[entry + MODULE_SIZE_OFF..entry + MODULE_SIZE_OFF + 4].try_into().unwrap()), module.size);
        assert_eq!(u16::from_le_bytes(block[entry + FULL_NAME_OFF..entry + FULL_NAME_OFF + 2].try_into().unwrap()), (module.full_name.encode_utf16().count() * 2) as u16);
    }

    #[test]
    fn plan_rejects_inconsistent_order_without_mutating_the_block() {
        let base = 0x1000_0000;
        let mut block = vec![0u8; BLOCK_BYTES];
        put_initial(&mut block, base);
        let head = LDR_OFF + LISTS[1].0;
        put_u64(&mut block, head, base + (LDR_OFF + LISTS[1].0) as u64);
        let original = block.clone();
        let module = NtModuleInput { base: 0x1800_0000, entry: 0, size: 0x1000, full_name: "x.dll", base_name: "x.dll" };
        assert_eq!(plan(&mut block, base, &module), Err(Error::Einval));
        assert_eq!(block, original);
    }
}
