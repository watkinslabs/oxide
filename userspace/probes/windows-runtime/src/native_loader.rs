use std::ffi::{c_void, CStr, CString};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use syscall::nt::NtService;
use syscall::nt_exec::NtWineUnixlibRegistration;
use syscall::UserPtr;

const MEMORY_WINE_REGISTER_UNIXLIB: u64 = syscall::nt_wine_unix::MEMORY_WINE_REGISTER_UNIXLIB as u64;
const STATUS_FAILURE_MASK: u64 = 0xc000_0000;

#[derive(Debug)]
pub enum NativeLoaderError {
    InvalidInput,
    Host(io::Error),
    DynamicLoader(String),
    MissingAttach,
    AttachStatus(i32),
    Status(u64),
}

/// Attach the current libc thread to the already-created Oxide NT identity.
/// The source-owned Wine ntdll adapter exports this before win32u is loaded,
/// so constructors cannot observe a null `NtCurrentTeb`.
pub fn attach_native_thread(unixlib_path: &Path, teb: u64, peb: u64) -> Result<(), NativeLoaderError> {
    if teb == 0 || peb == 0 { return Err(NativeLoaderError::InvalidInput); }
    let ntdll_path = unixlib_path.parent().ok_or(NativeLoaderError::InvalidInput)?.join("ntdll.so");
    let path = CString::new(ntdll_path.as_os_str().as_bytes()).map_err(|_| NativeLoaderError::InvalidInput)?;
    let symbol = CString::new("wine_oxide_attach_thread").expect("static symbol has no NUL");
    // SAFETY: the path is a validated NUL-terminated owned string. Keeping
    // this handle live for the process lifetime keeps the attached ntdll
    // implementation and its pthread key alive.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
    if handle.is_null() { return Err(NativeLoaderError::DynamicLoader(dlerror_message())); }
    // SAFETY: the source-owned adapter exports this exact two-address ABI.
    let attach = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    if attach.is_null() { return Err(NativeLoaderError::MissingAttach); }
    let attach: unsafe extern "C" fn(u64, u64) -> i32 = unsafe { std::mem::transmute(attach) };
    // SAFETY: both addresses are kernel-validated canonical Oxide user
    // addresses and the adapter only records the current thread association.
    let status = unsafe { attach(teb, peb) };
    if status != 0 { return Err(NativeLoaderError::AttachStatus(status)); }
    Ok(())
}

#[derive(Debug)]
struct LoadedObject {
    base: u64,
    end: u64,
    table_count: usize,
}

#[repr(C)]
struct Elf64Dyn {
    tag: i64,
    value: u64,
}

const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_GNU_HASH: i64 = 0x6ffffef5;

/// Resolve the loaded ELF object containing `symbol` and recover the symbol's
/// array length from its dynamic symbol table. The dynamic loader owns mapping,
/// relocations, TLS, IFUNC, and constructors; this code only observes the
/// already-live object before handing its callable table to the kernel.
/// # C: O(number of loaded ELF program headers + dynamic symbols)
unsafe extern "C" fn find_loaded_object(
    info: *mut libc::dl_phdr_info,
    _size: usize,
    opaque: *mut c_void,
) -> libc::c_int {
    // SAFETY: glibc invokes this callback with a valid `dl_phdr_info` for the
    // duration of the callback, and `opaque` is our exclusive result pointer.
    let info = unsafe { &*info };
    let result = unsafe { &mut *(opaque as *mut (u64, Option<LoadedObject>)) };
    if info.dlpi_addr as u64 != result.0 { return 0; }
    let mut base = u64::MAX;
    let mut end = 0u64;
    let mut dynamic = None;
    for index in 0..info.dlpi_phnum as usize {
        // SAFETY: dlpi_phdr points to the `dlpi_phnum` entries supplied by
        // the dynamic loader for this callback invocation.
        let phdr = unsafe { &*info.dlpi_phdr.add(index) };
        if phdr.p_type == libc::PT_LOAD {
            base = base.min(info.dlpi_addr as u64 + phdr.p_vaddr);
            end = end.max(info.dlpi_addr as u64 + phdr.p_vaddr + phdr.p_memsz);
        } else if phdr.p_type == libc::PT_DYNAMIC {
            dynamic = Some(info.dlpi_addr as u64 + phdr.p_vaddr);
        }
    }
    let Some(dynamic) = dynamic else { return 0; };
    let mut symtab = 0u64;
    let mut strtab = 0u64;
    let mut count = 0usize;
    let mut gnu_hash = 0u64;
    // DT_HASH's nchain is the portable bound for the regular dynamic symbol
    // table. GNU hash may coexist, but Wine's exported table is in dynsym.
    for index in 0..256usize {
        // SAFETY: PT_DYNAMIC is a loader-owned, null-terminated array of
        // Elf64_Dyn entries; the bound prevents malformed images looping.
        let dynent = unsafe { &*((dynamic as *const Elf64Dyn).add(index)) };
        match dynent.tag {
            DT_NULL => break,
            // The dynamic loader has already relocated DT_*_PTR values in a
            // live object; unlike PT_LOAD.vaddr, these are absolute VAs.
            DT_SYMTAB => symtab = dynent.value,
            DT_STRTAB => strtab = dynent.value,
            DT_HASH => {
                // SAFETY: DT_HASH points at the SysV hash header in this
                // same loaded object and has two u32 header words.
                let hash = dynent.value as *const u32;
                count = unsafe { (*hash.add(1)) as usize };
            }
            DT_GNU_HASH => gnu_hash = dynent.value,
            _ => {}
        }
    }
    if count == 0 && gnu_hash != 0 { count = gnu_hash_symbol_count(gnu_hash); }
    if base >= end || symtab == 0 || strtab == 0 || count == 0 { return 0; }
    let wanted = b"__wine_unix_call_funcs\0";
    for index in 0..count {
        // SAFETY: count came from DT_HASH and dynsym is part of this loaded
        // object; each entry is a fixed-size Elf64_Sym.
        let sym = unsafe { &*((symtab as *const libc::Elf64_Sym).add(index)) };
        let name = unsafe { CStr::from_ptr((strtab + sym.st_name as u64) as *const i8) };
        if name.to_bytes_with_nul() == wanted {
            result.1 = Some(LoadedObject { base, end, table_count: (sym.st_size as usize) / std::mem::size_of::<u64>() });
            break;
        }
    }
    1
}

fn gnu_hash_symbol_count(address: u64) -> usize {
    // GNU hash layout: header, bloom filter, bucket array, then chains. The
    // largest bucket index plus its terminating chain entry bounds dynsym.
    let header = address as *const u32;
    let (bucket_count, symbol_offset, bloom_size) = unsafe {
        (*header.add(0), *header.add(1), *header.add(2))
    };
    if bucket_count == 0 || bloom_size == 0 { return 0; }
    let bucket_address = address.saturating_add(16).saturating_add(bloom_size as u64 * 8);
    let bucket_ptr = bucket_address as *const u32;
    let chain_ptr = unsafe { bucket_ptr.add(bucket_count as usize) };
    let mut count = symbol_offset as usize;
    for bucket in 0..bucket_count as usize {
        let first = unsafe { *bucket_ptr.add(bucket) };
        if first < symbol_offset { continue; }
        let mut index = first as usize;
        for _ in 0..1_000_000usize {
            count = count.max(index.saturating_add(1));
            let chain = unsafe { *chain_ptr.add(index.saturating_sub(symbol_offset as usize)) };
            if chain & 1 != 0 { break; }
            index = index.saturating_add(1);
        }
    }
    count
}

/// Let the host ELF loader perform native loading, then publish the resolved
/// Wine Unix-call table. The handle is intentionally leaked: the table and
/// relocations remain valid for the lifetime of the NT process.
pub fn load_and_register_unixlib(path: &Path, name: &[u8]) -> Result<(), NativeLoaderError> {
    if path.as_os_str().as_bytes().contains(&0) || name.is_empty() || name.contains(&0) {
        return Err(NativeLoaderError::InvalidInput);
    }
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| NativeLoaderError::InvalidInput)?;
    let symbol = CString::new("__wine_unix_call_funcs").expect("static symbol has no NUL");
    // SAFETY: both strings are owned NUL-terminated C strings and RTLD_NOW
    // asks the platform loader to complete all relocation/TLS work here.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return Err(NativeLoaderError::DynamicLoader(dlerror_message()));
    }
    // SAFETY: `handle` is the live handle returned by dlopen and `symbol` is
    // NUL-terminated; dlsym returns the exported table address if present.
    let table_ptr = unsafe { libc::dlsym(handle, symbol.as_ptr()) } as u64;
    if table_ptr == 0 { return Err(NativeLoaderError::InvalidInput); }
    let mut address = MaybeUninit::<libc::Dl_info>::zeroed();
    // SAFETY: table_ptr came from dlsym; dladdr only writes the caller-owned
    // Dl_info structure and does not retain it.
    if unsafe { libc::dladdr(table_ptr as *const c_void, address.as_mut_ptr()) } == 0 { return Err(NativeLoaderError::InvalidInput); }
    // SAFETY: dladdr returned nonzero, so the output is initialized.
    let address = unsafe { address.assume_init() };
    let mut found: (u64, Option<LoadedObject>) = (address.dli_fbase as u64, None);
    // SAFETY: the callback obeys the dl_iterate_phdr ABI and `found` lives
    // until iteration returns.
    unsafe { libc::dl_iterate_phdr(Some(find_loaded_object), (&mut found as *mut _) as *mut c_void); }
    let object = found.1.ok_or(NativeLoaderError::InvalidInput)?;
    if object.table_count == 0 { return Err(NativeLoaderError::InvalidInput); }
    // SAFETY: dlsym identified an exported array whose dynamic symbol size is
    // bounded by the loader-owned object metadata just inspected.
    let table = unsafe { std::slice::from_raw_parts(table_ptr as *const u64, object.table_count) };
    register_unixlib(name, object.base, object.end, table)
}

fn dlerror_message() -> String {
    // SAFETY: dlerror returns either null or a NUL-terminated diagnostic owned
    // by the dynamic loader and valid until the next loader operation.
    let message = unsafe { libc::dlerror() };
    if message.is_null() { return "dynamic loader returned no diagnostic".into(); }
    unsafe { CStr::from_ptr(message) }.to_string_lossy().into_owned()
}

/// Publish a module that the userspace ELF loader has mapped and initialized.
/// The kernel validates only ownership bounds and callable targets; all ELF
/// relocation, TLS, constructor, and resolver work stays in this caller.
pub fn register_unixlib(name: &[u8], module_base: u64, module_end: u64, table: &[u64]) -> Result<(), NativeLoaderError> {
    if name.is_empty() || name.len() > 255 || name.iter().any(|byte| *byte == 0 || *byte > 0x7f)
        || module_base >= module_end || table.is_empty() || table.len() > 4096 { return Err(NativeLoaderError::InvalidInput); }
    let name_ptr = UserPtr::new(name.as_ptr() as u64).map_err(|_| NativeLoaderError::InvalidInput)?;
    let table_ptr = UserPtr::new(table.as_ptr() as u64).map_err(|_| NativeLoaderError::InvalidInput)?;
    let request = NtWineUnixlibRegistration {
        name: name_ptr, name_len: name.len() as u32, _name_padding: 0,
        module_base, module_end, table: table_ptr, entry_count: table.len() as u32, _table_padding: 0,
    };
    let result = unsafe { libc::syscall(NtService::QueryVirtualMemory.entry() as libc::c_long,
        u64::MAX, module_base, MEMORY_WINE_REGISTER_UNIXLIB, (&request as *const NtWineUnixlibRegistration) as u64,
        std::mem::size_of::<NtWineUnixlibRegistration>() as u64, 0u64) };
    if result == -1 { return Err(NativeLoaderError::Host(io::Error::last_os_error())); }
    let status = result as u64;
    if status & STATUS_FAILURE_MASK != 0 { return Err(NativeLoaderError::Status(status)); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_rejects_unowned_shapes_before_syscall() {
        assert!(matches!(register_unixlib(b"", 0x1000, 0x2000, &[0x1100]), Err(NativeLoaderError::InvalidInput)));
        assert!(matches!(register_unixlib(b"win32u.so", 0x2000, 0x1000, &[0x2100]), Err(NativeLoaderError::InvalidInput)));
        assert!(matches!(register_unixlib(b"win32u\0.so", 0x1000, 0x2000, &[0x1100]), Err(NativeLoaderError::InvalidInput)));
    }

    #[test]
    fn registration_selector_is_the_nt_memory_query_boundary() {
        assert_eq!(NtService::QueryVirtualMemory.entry() >> 32, syscall::nt::NT_SERVICE_NAMESPACE >> 32);
        assert_eq!(MEMORY_WINE_REGISTER_UNIXLIB, syscall::nt_wine_unix::MEMORY_WINE_REGISTER_UNIXLIB as u64);
    }

    #[test]
    fn loader_rejects_nul_in_native_path_before_dlopen() {
        assert!(matches!(load_and_register_unixlib(Path::new("/tmp/a\0b"), b"x"), Err(NativeLoaderError::InvalidInput)));
    }
}
