//! Dynamic catalog-backed PE loading for `LdrLoadDll`.

#[cfg(target_arch = "x86_64")]
use alloc::{string::String, vec, vec::Vec};
#[cfg(target_arch = "x86_64")]
use elf_load::pe_loader::{ImportResolver, PeExportModule, PeExportResolver};
use super::STATUS_INVALID_PARAMETER;
#[cfg(target_arch = "x86_64")]
use super::{LDR_LOAD_LIST_OFFSET, LIST_LINK_OFFSET, MAX_MODULE_SCAN, MODULE_BASE_NAME_OFFSET, MODULE_BASE_OFFSET, PEB_LDR_OFFSET, STATUS_DLL_NOT_FOUND, STATUS_SUCCESS, TEB_PEB_OFFSET};

#[cfg(target_arch = "aarch64")]
const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;

#[cfg(target_arch = "x86_64")]
struct Resolver<'a> { exports: PeExportResolver<'a>, ntdll: u64 }
#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
fn load_locked(cur: &sched::Task, name_descriptor: u64, module_output: u64) -> u64 {
    if name_descriptor == 0 || module_output == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(wanted) = read_wide_name(name_descriptor) else { return STATUS_INVALID_PARAMETER; };
    let Some(narrow_wanted) = narrow_name(&wanted) else { return STATUS_INVALID_PARAMETER; };
    let Some(teb_peb) = cur.nt_teb().checked_add(TEB_PEB_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let peb = super::read_u64(teb_peb);
    if peb == 0 { return STATUS_DLL_NOT_FOUND; }
    if let Some(base) = existing_module(peb, &wanted) {
        if uaccess::copy_to_user(module_output, &base.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_SUCCESS;
    }
    let Some(as_) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    if let Some(base) = load_native_unixlib(&narrow_wanted, &as_) {
        if uaccess::copy_to_user(module_output, &base.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_SUCCESS;
    }
    let Some(catalog) = cur.thread_group.nt_module_catalog() else { return STATUS_DLL_NOT_FOUND; };
    let Some((name, blob)) = catalog.modules().iter()
        .find(|module| pe::loader_name::matches_ascii(&narrow_wanted, &module.name))
        .map(|module| (module.name.clone(), module.blob.clone())) else { return STATUS_DLL_NOT_FOUND; };
    let (exports, ntdll) = match loaded_exports(peb, &catalog) { Ok(value) => value, Err(status) => return status };
    let resolver = Resolver { exports: PeExportResolver { modules: &exports }, ntdll };
    let catalog_source = &*catalog;
    let modules = match pe::discover_owned_modules_with_builtins(&name, &blob, &catalog_source,
        |candidate| pe::loader_name::matches_ascii(candidate, b"ntdll.dll") || loaded_module(peb, candidate)) {
        Ok(modules) => modules,
        Err(_) => return STATUS_DLL_NOT_FOUND,
    };
    let loaded = match elf_load::pe_loader::load_owned_pe_module_graph(&modules, &as_, &resolver, 0) {
        Ok(loaded) => loaded,
        Err(_) => return STATUS_DLL_NOT_FOUND,
    };
    let mut names = Vec::new();
    let mut inputs = Vec::new();
    for module in &modules {
        let base_name = narrow_base_name(&module.name);
        let full_name = if module.name.iter().any(|byte| *byte == b'\\' || *byte == b'/') { module.name.clone() } else {
            let mut path = b"C:\\Windows\\System32\\".to_vec(); path.extend_from_slice(&module.name); path
        };
        let full_name = match String::from_utf8(full_name) { Ok(value) => value, Err(_) => { unmap_all(&as_, &loaded); return STATUS_INVALID_PARAMETER; } };
        let base_name = match String::from_utf8(base_name) { Ok(value) => value, Err(_) => { unmap_all(&as_, &loaded); return STATUS_INVALID_PARAMETER; } };
        names.push((full_name, base_name));
    }
    for (loaded, (full_name, base_name)) in loaded.iter().zip(&names) {
        inputs.push(elf_load::process_env::NtModuleInput { base: loaded.image.base, entry: loaded.image.entry.as_u64(), size: loaded.image.size, full_name, base_name });
    }
    let initializers = match elf_load::pe_init::collect_dynamic_initializers(&loaded, &modules) {
        Ok(initializers) => initializers,
        Err(_) => { unmap_all(&as_, &loaded); return STATUS_INVALID_PARAMETER; },
    };
    // Validate the return-to-user transaction before publishing anything in
    // the PEB.  `publish_modules` mutates the process-visible loader lists;
    // discovering a missing frame after that point would leave dangling
    // entries if this syscall had to abort.
    let return_regs = if initializers.is_empty() {
        None
    } else {
        let regs = crate::arch_frame::current_user_regs();
        if regs.is_null() { unmap_all(&as_, &loaded); return STATUS_INVALID_PARAMETER; }
        Some(regs)
    };
    let trampoline = if initializers.is_empty() { None } else {
        let Some(return_entry) = hal::UserVirtAddr::new(crate::arch_frame::current_user_pc()) else { unmap_all(&as_, &loaded); return STATUS_INVALID_PARAMETER; };
        match elf_load::pe_init::map_dynamic_return(&as_, return_entry, &initializers) {
            Ok(trampoline) => trampoline,
            Err(_) => { unmap_all(&as_, &loaded); return STATUS_INVALID_PARAMETER; },
        }
    };
    let first_base = loaded.first().map(|module| module.image.base).unwrap_or(0);
    if uaccess::copy_to_user(module_output, &first_base.to_le_bytes()).is_err() {
        if let Some(trampoline) = &trampoline { unmap(&as_, trampoline.base.as_u64(), trampoline.bytes as u32); }
        unmap_all(&as_, &loaded);
        return STATUS_INVALID_PARAMETER;
    }
    if elf_load::process_env::publish_modules(peb, &inputs).is_err() {
        if let Some(trampoline) = &trampoline { unmap(&as_, trampoline.base.as_u64(), trampoline.bytes as u32); }
        unmap_all(&as_, &loaded);
        return STATUS_INVALID_PARAMETER;
    }
    for (loaded, module) in loaded.iter().zip(&modules) {
        elf_load::pe_modules::append(&as_, elf_load::pe_modules::PeRuntimeModule { base: loaded.image.base, size: loaded.image.size, exception_rva: loaded.image.exception_directory.0, exception_size: loaded.image.exception_directory.1 });
        if let Ok(Some(rvas)) = pe::parse(&module.blob).and_then(|parsed| parsed.export_rvas()) {
            elf_load::pe_modules::register_exports(&as_, loaded.image.base, rvas);
        }
        cur.thread_group.nt_module_refs.lock().push((loaded.image.base, 1));
    }
    if let Some(trampoline) = trampoline {
        // SAFETY: current_user_regs is the live syscall frame owned by this
        // dispatch; changing RIP redirects only this task's return-to-user path.
        unsafe { (*return_regs.expect("initializer path validated its return frame")).rip = trampoline.entry.as_u64(); }
    }
    STATUS_SUCCESS
}

#[cfg(target_arch = "x86_64")]
fn load_native_unixlib(name: &[u8], as_: &vmm::AddressSpace) -> Option<u64> {
    let path = native_unixlib_path(name)?;
    let bytes = vfs::read_abs(core::str::from_utf8(&path).ok()?).ok()?;
    let root = as_.root_pa();
    elf_load::unixlib::map_shared_object_with_resolver(&bytes, as_, |symbol| {
        elf_load::elf_modules::resolve_symbol(root, symbol)
    }).ok().map(|image| image.base)
}

#[cfg(target_arch = "x86_64")]
fn native_unixlib_path(name: &[u8]) -> Option<Vec<u8>> {
    let mut path = name.to_vec();
    if path.starts_with(b"\\??\\") { path.drain(..4); }
    for byte in &mut path { if *byte == b'\\' { *byte = b'/'; } }
    if path.starts_with(b"Z:") || path.starts_with(b"z:") { path.drain(..2); }
    let suffix = path.len().checked_sub(4)?;
    if !path[suffix..].eq_ignore_ascii_case(b".dll") { return None; }
    path.truncate(suffix);
    path.extend_from_slice(b".so");
    if path.first().copied() != Some(b'/') { return None; }
    Some(path)
}

#[cfg(all(test, target_arch = "x86_64"))]
mod native_unixlib_tests {
    use super::native_unixlib_path;

    #[test]
    fn nt_z_drive_unixlib_name_maps_to_vfs_so_path() {
        assert_eq!(native_unixlib_path(b"\\??\\Z:\\usr\\lib64\\wine\\x86_64-unix\\winevulkan.dll"),
            Some(b"/usr/lib64/wine/x86_64-unix/winevulkan.so".to_vec()));
    }

    #[test]
    fn non_absolute_or_non_dll_names_are_not_native_unixlibs() {
        assert_eq!(native_unixlib_path(b"kernel32.dll"), None);
        assert_eq!(native_unixlib_path(b"/tmp/module.exe"), None);
    }
}

#[cfg(target_arch = "aarch64")]
fn load_locked(_cur: &sched::Task, _name_descriptor: u64, _module_output: u64) -> u64 { STATUS_NOT_SUPPORTED }

#[cfg(target_arch = "x86_64")]
fn unmap_all(as_: &vmm::AddressSpace, modules: &[elf_load::pe_loader::PeLoadedModule<'_>]) {
    for module in modules { unmap(as_, module.image.base, module.image.size); }
}

#[cfg(target_arch = "x86_64")]
fn existing_module(peb: u64, wanted: &[u8]) -> Option<u64> {
    let ldr = super::read_u64(peb.checked_add(PEB_LDR_OFFSET)?);
    if ldr == 0 { return None; }
    let head = ldr.checked_add(LDR_LOAD_LIST_OFFSET)?;
    let mut entry = super::read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        let name = super::read_module_name(entry.checked_add(MODULE_BASE_NAME_OFFSET)?);
        if pe::loader_name::matches_utf16(wanted, &name) { return Some(super::read_u64(entry.checked_add(MODULE_BASE_OFFSET)?)); }
        entry = super::read_u64(entry.checked_add(LIST_LINK_OFFSET)?);
    }
    None
}

#[cfg(target_arch = "x86_64")]
fn loaded_module(peb: u64, wanted: &[u8]) -> bool {
    let Some(ldr_address) = peb.checked_add(PEB_LDR_OFFSET) else { return false; };
    let ldr = super::read_u64(ldr_address);
    if ldr == 0 { return false; }
    let Some(head) = ldr.checked_add(LDR_LOAD_LIST_OFFSET) else { return false; };
    let mut entry = super::read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        let Some(name_address) = entry.checked_add(MODULE_BASE_NAME_OFFSET) else { return false; };
        let wide = super::read_module_name(name_address);
        if narrow_name(&wide).map(|name| pe::loader_name::matches_ascii(wanted, &name)).unwrap_or(false) { return true; }
        let Some(link_address) = entry.checked_add(LIST_LINK_OFFSET) else { return false; };
        entry = super::read_u64(link_address);
    }
    false
}

#[cfg(target_arch = "x86_64")]
fn loaded_exports<'a>(peb: u64, catalog: &'a pe::catalog::ModuleCatalog) -> Result<(Vec<PeExportModule<'a>>, u64), u64> {
    let ldr = super::read_u64(peb.checked_add(PEB_LDR_OFFSET).ok_or(STATUS_INVALID_PARAMETER)?);
    if ldr == 0 { return Err(STATUS_DLL_NOT_FOUND); }
    let head = ldr.checked_add(LDR_LOAD_LIST_OFFSET).ok_or(STATUS_INVALID_PARAMETER)?;
    let mut entry = super::read_u64(head);
    let mut exports = Vec::new();
    let mut ntdll = 0;
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        let name_address = entry.checked_add(MODULE_BASE_NAME_OFFSET).ok_or(STATUS_INVALID_PARAMETER)?;
        let wide = super::read_module_name(name_address);
        let narrow = narrow_name(&wide).ok_or(STATUS_INVALID_PARAMETER)?;
        let base = super::read_u64(entry.checked_add(MODULE_BASE_OFFSET).ok_or(STATUS_INVALID_PARAMETER)?);
        if narrow.eq_ignore_ascii_case(b"ntdll.dll") { ntdll = base; }
        if let Some(module) = catalog.modules().iter().find(|module| pe::loader_name::matches_ascii(&narrow, &module.name)) {
            let image = pe::parse(&module.blob).map_err(|_| STATUS_INVALID_PARAMETER)?;
            exports.push(PeExportModule { name: &module.name, image, base });
        }
        entry = super::read_u64(entry.checked_add(LIST_LINK_OFFSET).ok_or(STATUS_INVALID_PARAMETER)?);
    }
    if ntdll == 0 { return Err(STATUS_DLL_NOT_FOUND); }
    Ok((exports, ntdll))
}

#[cfg(target_arch = "x86_64")]
fn read_wide_name(descriptor: u64) -> Option<Vec<u8>> {
    let mut raw = [0u8; 16]; uaccess::copy_from_user(&mut raw, descriptor).ok()?;
    let len = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let max = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    if len == 0 || len > max || len & 1 != 0 || len > 32 * 1024 || buffer == 0 { return None; }
    let mut value = vec![0u8; len]; uaccess::copy_from_user(&mut value, buffer).ok()?; Some(value)
}

#[cfg(target_arch = "x86_64")]
fn narrow_name(wide: &[u8]) -> Option<Vec<u8>> {
    if wide.len() & 1 != 0 { return None; }
    let mut out = Vec::with_capacity(wide.len() / 2);
    for pair in wide.chunks_exact(2) { if pair[1] != 0 { return None; } out.push(pair[0]); }
    Some(out)
}
#[cfg(target_arch = "x86_64")]
fn narrow_base_name(name: &[u8]) -> Vec<u8> { name.rsplit(|byte| *byte == b'\\' || *byte == b'/').next().unwrap_or(name).to_vec() }
#[cfg(target_arch = "x86_64")]
fn unmap(as_: &vmm::AddressSpace, base: u64, size: u32) { if let Some(base) = hal::UserVirtAddr::new(base) { let _ = as_.munmap(base, size as usize); } }
