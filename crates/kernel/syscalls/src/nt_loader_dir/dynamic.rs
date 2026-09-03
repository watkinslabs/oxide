//! Dynamic catalog-backed PE loading for `LdrLoadDll`.

use alloc::{string::String, vec, vec::Vec};
use elf_load::pe_loader::{ImportResolver, PeExportModule, PeExportResolver};
use super::{LDR_LOAD_LIST_OFFSET, LIST_LINK_OFFSET, MAX_MODULE_SCAN, MODULE_BASE_NAME_OFFSET, MODULE_BASE_OFFSET, PEB_LDR_OFFSET, STATUS_DLL_NOT_FOUND, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, TEB_PEB_OFFSET};

struct Resolver<'a> { exports: PeExportResolver<'a>, ntdll: u64 }
impl ImportResolver for Resolver<'_> {
    fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
        if dll.eq_ignore_ascii_case(b"ntdll.dll") {
            if let pe::ImportThunk::Name { name, .. } = import {
                if let Some(address) = elf_load::pe_loader::resolve_nt_runtime_export(self.ntdll, name) { return Ok(address); }
            }
        }
        self.exports.resolve(dll, import)
    }
}

pub(super) fn load(name_descriptor: u64, module_output: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || cur.tid == 0 { return STATUS_INVALID_PARAMETER; }
    let outcome = unsafe { cur.thread_group.nt_peb_lock.wait(cur.tid as u64, 0, timekeeper::monotonic_ns) };
    if outcome != sched::WaitOutcome::Ready { return STATUS_INVALID_PARAMETER; }
    let status = load_locked(cur, name_descriptor, module_output);
    let _ = cur.thread_group.nt_peb_lock.release(cur.tid as u64);
    status
}

fn load_locked(cur: &sched::Task, name_descriptor: u64, module_output: u64) -> u64 {
    if name_descriptor == 0 || module_output == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(wanted) = read_wide_name(name_descriptor) else { return STATUS_INVALID_PARAMETER; };
    let Some(narrow_wanted) = narrow_name(&wanted) else { return STATUS_INVALID_PARAMETER; };
    let peb = super::read_u64(cur.nt_teb().saturating_add(TEB_PEB_OFFSET));
    if peb == 0 { return STATUS_DLL_NOT_FOUND; }
    if let Some(base) = existing_module(peb, &wanted) {
        if uaccess::copy_to_user(module_output, &base.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_SUCCESS;
    }
    let Some(as_) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    let Some(catalog) = cur.thread_group.nt_module_catalog() else { return STATUS_DLL_NOT_FOUND; };
    let Some((name, blob)) = catalog.modules().iter()
        .find(|module| pe::loader_name::matches_ascii(&narrow_wanted, &module.name))
        .map(|module| (module.name.clone(), module.blob.clone())) else { return STATUS_DLL_NOT_FOUND; };
    let (exports, ntdll) = match loaded_exports(peb, &catalog) { Ok(value) => value, Err(status) => return status };
    let resolver = Resolver { exports: PeExportResolver { modules: &exports }, ntdll };
    let image = match elf_load::pe_loader::load_pe_image_with_resolver(&blob, &as_, &resolver) {
        Ok(image) => image,
        Err(_) => return STATUS_DLL_NOT_FOUND,
    };
    let base_name = narrow_base_name(&name);
    let full_name = if name.iter().any(|byte| *byte == b'\\' || *byte == b'/') { name.clone() } else {
        let mut path = b"C:\\Windows\\System32\\".to_vec(); path.extend_from_slice(&name); path
    };
    let full_name = match String::from_utf8(full_name) { Ok(value) => value, Err(_) => { unmap(&as_, image.base, image.size); return STATUS_INVALID_PARAMETER; } };
    let base_name = match String::from_utf8(base_name) { Ok(value) => value, Err(_) => { unmap(&as_, image.base, image.size); return STATUS_INVALID_PARAMETER; } };
    let module = elf_load::process_env::NtModuleInput { base: image.base, entry: image.entry.as_u64(), size: image.size, full_name: &full_name, base_name: &base_name };
    if elf_load::process_env::publish_module(peb, &module).is_err() {
        unmap(&as_, image.base, image.size);
        return STATUS_INVALID_PARAMETER;
    }
    elf_load::pe_modules::append(&as_, elf_load::pe_modules::PeRuntimeModule { base: image.base, size: image.size, exception_rva: image.exception_directory.0, exception_size: image.exception_directory.1 });
    if let Ok(Some(rvas)) = pe::parse(&blob).and_then(|parsed| parsed.export_rvas()) {
        elf_load::pe_modules::register_exports(&as_, image.base, rvas);
    }
    cur.thread_group.nt_module_refs.lock().push((image.base, 1));
    if uaccess::copy_to_user(module_output, &image.base.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn existing_module(peb: u64, wanted: &[u8]) -> Option<u64> {
    let ldr = super::read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if ldr == 0 { return None; }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = super::read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        let name = super::read_module_name(entry.saturating_add(MODULE_BASE_NAME_OFFSET));
        if pe::loader_name::matches_utf16(wanted, &name) { return Some(super::read_u64(entry.saturating_add(MODULE_BASE_OFFSET))); }
        entry = super::read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    None
}

fn loaded_exports<'a>(peb: u64, catalog: &'a pe::catalog::ModuleCatalog) -> Result<(Vec<PeExportModule<'a>>, u64), u64> {
    let ldr = super::read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if ldr == 0 { return Err(STATUS_DLL_NOT_FOUND); }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = super::read_u64(head);
    let mut exports = Vec::new();
    let mut ntdll = 0;
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        let wide = super::read_module_name(entry.saturating_add(MODULE_BASE_NAME_OFFSET));
        let narrow = narrow_name(&wide).ok_or(STATUS_INVALID_PARAMETER)?;
        let base = super::read_u64(entry.saturating_add(MODULE_BASE_OFFSET));
        if narrow.eq_ignore_ascii_case(b"ntdll.dll") { ntdll = base; }
        if let Some(module) = catalog.modules().iter().find(|module| pe::loader_name::matches_ascii(&narrow, &module.name)) {
            let image = pe::parse(&module.blob).map_err(|_| STATUS_INVALID_PARAMETER)?;
            exports.push(PeExportModule { name: &module.name, image, base });
        }
        entry = super::read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    if ntdll == 0 { return Err(STATUS_DLL_NOT_FOUND); }
    Ok((exports, ntdll))
}

fn read_wide_name(descriptor: u64) -> Option<Vec<u8>> {
    let mut raw = [0u8; 16]; uaccess::copy_from_user(&mut raw, descriptor).ok()?;
    let len = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let max = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    if len == 0 || len > max || len & 1 != 0 || len > 32 * 1024 || buffer == 0 { return None; }
    let mut value = vec![0u8; len]; uaccess::copy_from_user(&mut value, buffer).ok()?; Some(value)
}

fn narrow_name(wide: &[u8]) -> Option<Vec<u8>> {
    if wide.len() & 1 != 0 { return None; }
    let mut out = Vec::with_capacity(wide.len() / 2);
    for pair in wide.chunks_exact(2) { if pair[1] != 0 { return None; } out.push(pair[0]); }
    Some(out)
}
fn narrow_base_name(name: &[u8]) -> Vec<u8> { name.rsplit(|byte| *byte == b'\\' || *byte == b'/').next().unwrap_or(name).to_vec() }
fn unmap(as_: &vmm::AddressSpace, base: u64, size: u32) { if let Some(base) = hal::UserVirtAddr::new(base) { let _ = as_.munmap(base, size as usize); } }
