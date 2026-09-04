use alloc::{string::String, vec, vec::Vec};
use hal::UserVirtAddr;
use pe::Error;
use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};

mod publish;
#[cfg(target_os = "oxide-kernel")]
pub use publish::{publish_module, publish_modules};

pub const X64_SHADOW_SPACE: u64 = 32;
#[cfg(test)]
const PAGE: usize = 4096;
const THREAD_TEB_BYTES: usize = 0x4000;
const TEB_SYSCALL_FRAME_OFFSET: usize = 0x378;
const TEB_ACTIVATION_CONTEXT_STACK_OFFSET: usize = 0x2c8;
const TEB_ACTIVATION_CONTEXT_STACK_INLINE: usize = 0x290;
const THREAD_SYSCALL_FRAME_OFF: usize = 0x3000;
const PROCESS_SYSCALL_FRAME_OFF: usize = 0x7000;
pub const NT_DEBUG_INFO_OFFSET: u64 = 0x2f00;
const PEB_OFF: usize = 0x000;
const TEB_OFF: usize = 0x100;
const TEB_STACK_BASE_OFF: usize = 0x08;
const TEB_STACK_LIMIT_OFF: usize = 0x10;
const TEB_DEALLOCATION_STACK_OFF: usize = 0x1478;
const TLS_OFF: usize = 0x180;
// TEB64 offsets from Wine's winternl.h.  Keep these named separately from
// TLS_OFF: the latter is the ThreadLocalStoragePointer used by ntdll, while
// the Win32 TLS API addresses the inline slots below directly.
const TEB_CURRENT_LOCALE_OFF: usize = 0x108;
#[cfg(test)]
const TEB_TLS_SLOTS_OFF: usize = 0x1480;
#[cfg(test)]
const TEB_TLS_SLOTS: usize = 64;
#[cfg(test)]
const TEB_TLS_EXPANSION_SLOTS_OFF: usize = 0x1780;
// Keep the process-parameter structure clear of PEB64's inline TLS expansion
// bitmap at 0x240..0x2c0. The loader list/module records follow it.
const PARAM_OFF: usize = 0x300;
const PARAM_SIZE: u32 = (ENV_OFF - PARAM_OFF) as u32;
const PARAM_FLAGS_NORMALIZED: u32 = 1;
const PARAM_ENVIRONMENT_SIZE_OFF: usize = 0x3f0;
const LDR_OFF: usize = 0x1800;
const MOD_OFF: usize = 0x1900;
const MOD_STRIDE: usize = 0x70;
const MAX_MODULES: usize = 64;
const ENV_OFF: usize = 0x1000;
const STR_OFF: usize = 0x4000;
const CURRENT_DIR: &str = "C:\\Windows";
const CURRENT_DIR_STORAGE: usize = 0x400;
const API_SET_OFF: usize = 0x6000;
const PEB_PROCESS_HEAP_OFF: usize = 0x30;
const PEB_NUMBER_OF_PROCESSORS_OFF: usize = 0xb8;
const PROCESS_HEAP_HANDLE: u64 = 1;
const INITIAL_PROCESSOR_COUNT: u32 = 1;
// Storage for the RTL_BITMAP descriptors. The bit buffers themselves live at
// the PEB offsets prescribed by winternl.h, while these descriptors are kept
// in otherwise-unused environment space below the API-set map.
const TLS_BITMAP_DESC_OFF: usize = 0x6800;
const TLS_EXP_BITMAP_DESC_OFF: usize = 0x6820;
const BLOCK_BYTES: usize = 0x8000;
#[cfg(target_os = "oxide-kernel")]
const USER_SHARED_DATA_BASE: u64 = 0x7ffe_0000;
#[cfg(target_os = "oxide-kernel")]
const USER_SHARED_DATA_BYTES: usize = 0x1000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtProcessEnvironment {
    pub base: UserVirtAddr,
    pub peb: UserVirtAddr,
    pub teb: UserVirtAddr,
    pub process_parameters: UserVirtAddr,
    pub loader_data: UserVirtAddr,
    pub environment: UserVirtAddr,
    pub tls: UserVirtAddr,
    pub api_set_map: UserVirtAddr,
    pub bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentInput<'a> {
    pub image_base: u64,
    pub image_size: u32,
    pub image_path: &'a str,
    pub command_line: &'a str,
    pub environment: &'a [(&'a str, &'a str)],
    pub process_id: u32,
    pub thread_id: u32,
}

/// Windows process-parameter values copied from a parent into a new image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtProcessParameters<'a> {
    pub current_directory: &'a str,
    pub current_directory_handle: u64,
    pub console_handle: u64,
    pub standard_handles: [u64; 3],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtModuleInput<'a> {
    pub base: u64,
    pub entry: u64,
    pub size: u32,
    pub full_name: &'a str,
    pub base_name: &'a str,
}

/// Build and map the initial PEB/TEB/process-parameters block.
/// # C: O(image_path + command_line + environment)
pub fn build(input: &EnvironmentInput<'_>, as_: &AddressSpace) -> Result<NtProcessEnvironment, Error> {
    let base_name = input.image_path.rsplit(['\\', '/']).next().unwrap_or(input.image_path);
    let module = NtModuleInput { base: input.image_base, entry: input.image_base, size: input.image_size, full_name: input.image_path, base_name };
    build_with_modules(input, core::slice::from_ref(&module), as_)
}

/// Allocate the first page of a thread-local NT environment for a thread
/// created after process exec. The PEB remains process-owned; this page is
/// thread-owned and carries the TEB self pointer, IDs, PEB pointer, and TLS.
/// # C: O(1)
pub fn build_thread_teb(process_id: u32, thread_id: u32, peb: u64, as_: &AddressSpace) -> Result<UserVirtAddr, Error> {
    let reservation = as_.mmap(None, THREAD_TEB_BYTES, VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE, VmaBacking::Anonymous, false).map_err(|_| Error::Einval)?;
    let base = reservation.as_u64();
    let mut teb = vec![0u8; THREAD_TEB_BYTES];
    put_u64(&mut teb, 0x30, base);
    put_u64(&mut teb, 0x60, peb);
    put_u32(&mut teb, 0x40, process_id);
    put_u32(&mut teb, 0x48, thread_id);
    put_u64(&mut teb, 0x58, base + 0x180);
    put_u64(&mut teb, TEB_ACTIVATION_CONTEXT_STACK_OFFSET,
        base + TEB_ACTIVATION_CONTEXT_STACK_INLINE as u64);
    put_u32(&mut teb, TEB_CURRENT_LOCALE_OFF, 0x409);
    // TlsSlots and TlsExpansionSlots are deliberately zero-initialized.  A
    // later TlsAlloc/TlsSetValue call owns their contents and must not inherit
    // values from the process that created this thread.
    put_u64(&mut teb, TEB_SYSCALL_FRAME_OFFSET, base + THREAD_SYSCALL_FRAME_OFF as u64);
    as_.munmap(reservation, THREAD_TEB_BYTES).map_err(|_| Error::Einval)?;
    let data = as_.stash_bytes(teb.into_boxed_slice());
    if as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(reservation), THREAD_TEB_BYTES,
        VmaProt::READ | VmaProt::WRITE, VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE, VmaBacking::KernelBytes { data, off: 0 }).is_err() {
        let _ = as_.munmap(reservation, THREAD_TEB_BYTES);
        return Err(Error::Einval);
    }
    Ok(reservation)
}

/// Build the initial process environment and publish the supplied loader list.
/// # C: O(image_path + command_line + environment + N_modules)
pub fn build_with_modules(input: &EnvironmentInput<'_>, modules: &[NtModuleInput<'_>], as_: &AddressSpace) -> Result<NtProcessEnvironment, Error> {
    build_with_modules_and_stack(input, modules, 0, 0, as_)
}

/// Build the initial environment while publishing the already allocated
/// process stack in the TEB NT_TIB. Zero bounds are retained for callers that
/// construct only an environment fixture; the PE exec path always supplies
/// the real VMA bounds from its single address space.
/// # C: O(image_path + command_line + environment + N_modules)
pub fn build_with_modules_and_stack(input: &EnvironmentInput<'_>, modules: &[NtModuleInput<'_>], stack_base: u64, stack_top: u64, as_: &AddressSpace) -> Result<NtProcessEnvironment, Error> {
    build_with_modules_and_params_and_stack(input, modules, &NtProcessParameters {
        current_directory: CURRENT_DIR, current_directory_handle: 0,
        console_handle: 0, standard_handles: [0; 3],
    }, stack_base, stack_top, as_)
}

/// Build the initial environment with caller-supplied process parameters.
/// # C: O(image_path + command_line + environment + N_modules)
pub fn build_with_modules_and_params(input: &EnvironmentInput<'_>, modules: &[NtModuleInput<'_>], params: &NtProcessParameters<'_>, as_: &AddressSpace) -> Result<NtProcessEnvironment, Error> {
    build_with_modules_and_params_and_stack(input, modules, params, 0, 0, as_)
}

/// Build process parameters and publish the canonical stack VMA in NT_TIB.
/// # C: O(image_path + command_line + environment + N_modules)
pub fn build_with_modules_and_params_and_stack(input: &EnvironmentInput<'_>, modules: &[NtModuleInput<'_>], params: &NtProcessParameters<'_>, stack_base: u64, stack_top: u64, as_: &AddressSpace) -> Result<NtProcessEnvironment, Error> {
    if modules.is_empty() || modules.len() > MAX_MODULES { return Err(Error::Einval); }
    let (stack_base, stack_top) = if stack_base == 0 && stack_top != 0 {
        let top = UserVirtAddr::new(stack_top).ok_or(Error::Einval)?;
        let probe = UserVirtAddr::new(stack_top.checked_sub(1).ok_or(Error::Einval)?).ok_or(Error::Einval)?;
        match as_.find_vma(probe) {
            Some(vma) => {
                if vma.end != top || !matches!(vma.backing, VmaBacking::Anonymous) { return Err(Error::Einval); }
                (vma.start.as_u64(), stack_top)
            },
            None => (0, 0),
        }
    } else { (stack_base, stack_top) };
    if (stack_base == 0) != (stack_top == 0) || stack_base > stack_top { return Err(Error::Einval); }
    let image_path = utf16(input.image_path)?;
    let command_line = utf16(input.command_line)?;
    let mut env = Vec::new();
    for &(name, value) in input.environment {
        if name.contains('\0') || value.contains('\0') { return Err(Error::Einval); }
        env.extend(utf16(&(String::from(name) + "=" + value))?);
    }
    env.push(0);
    let mut strings = Vec::new();
    strings.extend_from_slice(&image_path);
    let image_path_off = STR_OFF;
    let command_off = STR_OFF + strings.len() * 2;
    strings.extend_from_slice(&command_line);
    let current_dir = utf16(params.current_directory)?;
    let current_dir_off = STR_OFF + strings.len() * 2;
    strings.extend_from_slice(&current_dir);
    let mut module_offsets = Vec::new();
    let mut module_text_off = current_dir_off + CURRENT_DIR_STORAGE;
    for module in modules {
        let full = utf16(module.full_name)?;
        let base = utf16(module.base_name)?;
        module_offsets.push((module_text_off, full.len(), module_text_off + full.len() * 2, base.len()));
        module_text_off = module_text_off.checked_add((full.len() + base.len()) * 2).ok_or(Error::Einval)?;
    }
    let env_off = ENV_OFF;
    let total = env_off.checked_add(env.len() * 2).ok_or(Error::Einval)?;
    if total > STR_OFF || module_text_off > API_SET_OFF { return Err(Error::Einval); }
    let reservation = as_.mmap(None, BLOCK_BYTES, VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE, VmaBacking::Anonymous, false).map_err(|_| Error::Einval)?;
    let base = reservation.as_u64();
    let mut block = vec![0u8; BLOCK_BYTES];
    put_u64(&mut block, PEB_OFF + 0x10, input.image_base);
    put_u64(&mut block, PEB_OFF + 0x18, base + LDR_OFF as u64);
    put_u64(&mut block, PEB_OFF + 0x20, base + PARAM_OFF as u64);
    put_u64(&mut block, PEB_OFF + PEB_PROCESS_HEAP_OFF, PROCESS_HEAP_HANDLE);
    put_u32(&mut block, PEB_OFF + PEB_NUMBER_OF_PROCESSORS_OFF, INITIAL_PROCESSOR_COUNT);
    put_u64(&mut block, PEB_OFF + 0x68, base + API_SET_OFF as u64);
    // RTL_USER_PROCESS_PARAMETERS is normalized: embedded string pointers
    // are absolute, Size ends immediately before the separate environment
    // allocation, and EnvironmentSize includes its terminating WCHAR.
    put_u32(&mut block, PARAM_OFF, PARAM_SIZE);
    put_u32(&mut block, PARAM_OFF + 4, PARAM_SIZE);
    put_u32(&mut block, PARAM_OFF + 8, PARAM_FLAGS_NORMALIZED);
    put_u64(&mut block, PEB_OFF + 0x78, 0);
    // PEB.TlsBitmap/TlsExpansionBitmap are RTL_BITMAP pointers at these
    // x86-64 offsets. Wine's kernelbase TlsAlloc depends on both descriptors
    // being valid before any DLL process-attach routine asks for a TLS slot.
    put_u64(&mut block, PEB_OFF + 0x78, base + TLS_BITMAP_DESC_OFF as u64);
    // TlsBitmapBits is two ULONGs (64 slots), not an RTL_BITMAP header. The
    // header is out-of-line and points back at this inline bit storage.
    put_u32(&mut block, PEB_OFF + 0x80, 0x0001_0001);
    put_u32(&mut block, PEB_OFF + 0x84, 0);
    put_u64(&mut block, PEB_OFF + 0x238, base + TLS_EXP_BITMAP_DESC_OFF as u64);
    // TlsExpansionBitmapBits is 32 ULONGs (1024 slots), initially clear.
    put_u32(&mut block, TLS_BITMAP_DESC_OFF, 64);
    put_u64(&mut block, TLS_BITMAP_DESC_OFF + 8, base + PEB_OFF as u64 + 0x80);
    put_u32(&mut block, TLS_EXP_BITMAP_DESC_OFF, 1024);
    put_u64(&mut block, TLS_EXP_BITMAP_DESC_OFF + 8, base + PEB_OFF as u64 + 0x240);
    put_u64(&mut block, TEB_OFF + 0x30, base + TEB_OFF as u64);
    put_u64(&mut block, TEB_OFF + TEB_STACK_BASE_OFF, stack_top);
    put_u64(&mut block, TEB_OFF + TEB_STACK_LIMIT_OFF, stack_base);
    put_u64(&mut block, TEB_OFF + 0x60, base + PEB_OFF as u64);
    put_u32(&mut block, TEB_OFF + 0x40, input.process_id);
    put_u32(&mut block, TEB_OFF + 0x48, input.thread_id);
    put_u64(&mut block, TEB_OFF + 0x58, base + TLS_OFF as u64);
    put_u64(&mut block, TEB_OFF + TEB_ACTIVATION_CONTEXT_STACK_OFFSET,
        base + TEB_OFF as u64 + TEB_ACTIVATION_CONTEXT_STACK_INLINE as u64);
    put_u32(&mut block, TEB_OFF + TEB_CURRENT_LOCALE_OFF, 0x409);
    put_u64(&mut block, TEB_OFF + TEB_DEALLOCATION_STACK_OFF, stack_base);
    // The fixed TEB block contains all 64 native TLS slots inline.  The
    // expansion pointer stays NULL until a slot >= 64 is requested, matching
    // kernelbase's TlsAlloc/TlsSetValue behavior.
    put_u64(&mut block, TEB_OFF + TEB_SYSCALL_FRAME_OFFSET, base + PROCESS_SYSCALL_FRAME_OFF as u64);
    put_u64(&mut block, PARAM_OFF + 0x10, params.console_handle);
    put_u64(&mut block, PARAM_OFF + 0x38, params.current_directory_handle);
    for (offset, handle) in [0x20usize, 0x28, 0x30].into_iter().zip(params.standard_handles) {
        put_u64(&mut block, PARAM_OFF + offset, handle);
    }
    put_unicode(&mut block, PARAM_OFF + 0x60, &image_path, base + image_path_off as u64);
    put_unicode(&mut block, PARAM_OFF + 0x70, &command_line, base + command_off as u64);
    put_unicode_with_capacity(&mut block, PARAM_OFF + 0x40, &current_dir,
        base + current_dir_off as u64, CURRENT_DIR_STORAGE);
    put_u64(&mut block, PARAM_OFF + 0x80, base + env_off as u64);
    put_u32(&mut block, LDR_OFF, 0x58);
    block[LDR_OFF + 4] = 1;
    let mut loader_list = pe::loader_list::LoaderList::new(MAX_MODULES);
    for index in 0..modules.len() { loader_list.insert_tail(index).map_err(|_| Error::Einval)?; }
    for (list, (head, link)) in [(0usize, (0x10usize, 0usize)), (1, (0x20, 0x10)), (2, (0x30, 0x20))] {
        let topology = loader_list.head(list).ok_or(Error::Einval)?;
        let first = base + (MOD_OFF + topology.next * MOD_STRIDE + link) as u64;
        let last = base + (MOD_OFF + topology.prev * MOD_STRIDE + link) as u64;
        put_u64(&mut block, LDR_OFF + head, first); put_u64(&mut block, LDR_OFF + head + 8, last);
        for index in 0..modules.len() {
            let entry = MOD_OFF + index * MOD_STRIDE + link;
            let topology = loader_list.link(index, list).ok_or(Error::Einval)?;
            let next = if topology.next < MAX_MODULES { base + (MOD_OFF + topology.next * MOD_STRIDE + link) as u64 } else { base + (LDR_OFF + head) as u64 };
            let prev = if topology.prev < MAX_MODULES { base + (MOD_OFF + topology.prev * MOD_STRIDE + link) as u64 } else { base + (LDR_OFF + head + 8) as u64 };
            put_u64(&mut block, entry, next); put_u64(&mut block, entry + 8, prev);
        }
    }
    for (index, module) in modules.iter().enumerate() {
        #[cfg(feature = "debug-faultdiag")]
        {
            klog::write_raw(b"[WINDOWS-PE-ENV] base=");
            klog::write_hex_u64(module.base);
            klog::write_raw(b" entry=");
            klog::write_hex_u64(module.entry);
            klog::write_raw(b" size=");
            klog::write_hex_u64(module.size as u64);
            klog::write_raw(b"\n");
        }
        let entry = MOD_OFF + index * MOD_STRIDE;
        put_u64(&mut block, entry + 0x30, module.base);
        put_u64(&mut block, entry + 0x38, module.entry);
        put_u32(&mut block, entry + 0x40, module.size);
        let (full_off, full_len, base_off, base_len) = module_offsets[index];
        let full = utf16(module.full_name)?; let name = utf16(module.base_name)?;
        put_unicode(&mut block, entry + 0x48, &full, base + full_off as u64);
        put_unicode(&mut block, entry + 0x58, &name, base + base_off as u64);
        copy_u16(&mut block, full_off, &full); copy_u16(&mut block, base_off, &name);
        let _ = (full_len, base_len);
    }
    copy_u16(&mut block, image_path_off, &image_path);
    copy_u16(&mut block, command_off, &command_line);
    copy_u16(&mut block, current_dir_off, &current_dir);
    copy_u16(&mut block, env_off, &env);
    put_u64(&mut block, PARAM_OFF + PARAM_ENVIRONMENT_SIZE_OFF, (env.len() * 2) as u64);
    // Wine's x86-64 syscall dispatcher keeps its register/return frame in a
    // thread-data slot at TEB+0x378. The initial thread has no Wine-created
    // Unix thread bootstrap to allocate it, so reserve the same 0x300-byte
    // frame in the synthetic TEB block and publish its pointer explicitly.
    put_api_set_map(&mut block, API_SET_OFF)?;
    as_.munmap(reservation, BLOCK_BYTES).map_err(|_| Error::Einval)?;
    let data = as_.stash_bytes(block.into_boxed_slice());
    if as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(reservation), BLOCK_BYTES,
        VmaProt::READ | VmaProt::WRITE, VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE, VmaBacking::KernelBytes { data, off: 0 }).is_err() {
        let _ = as_.munmap(reservation, BLOCK_BYTES); return Err(Error::Einval);
    }
    if map_user_shared_data(as_).is_err() {
        let _ = as_.munmap(reservation, BLOCK_BYTES); return Err(Error::Einval);
    }
    Ok(NtProcessEnvironment { base: reservation, peb: addr(base, PEB_OFF)?, teb: addr(base, TEB_OFF)?, process_parameters: addr(base, PARAM_OFF)?, loader_data: addr(base, LDR_OFF)?, environment: addr(base, ENV_OFF)?, tls: addr(base, TLS_OFF)?, api_set_map: addr(base, API_SET_OFF)?, bytes: BLOCK_BYTES })
}

#[cfg(target_os = "oxide-kernel")]
fn map_user_shared_data(as_: &AddressSpace) -> Result<(), Error> {
    let base = UserVirtAddr::new(USER_SHARED_DATA_BASE).ok_or(Error::Einval)?;
    let mut page = vec![0u8; USER_SHARED_DATA_BYTES];
    let root = utf16("C:\\Windows")?;
    for (index, value) in root.iter().enumerate() { put_u16(&mut page, 0x30 + index * 2, *value); }
    put_u32(&mut page, 0x260, 0x0a000000);
    put_u32(&mut page, 0x26c, 10);
    put_u32(&mut page, 0x270, 0);
    let data = as_.stash_bytes(page.into_boxed_slice());
    as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(base), USER_SHARED_DATA_BYTES,
        VmaProt::READ, VmaProt::READ, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data, off: 0 }).map_err(|_| Error::Einval)?;
    Ok(())
}

#[cfg(not(target_os = "oxide-kernel"))]
fn map_user_shared_data(_as_: &AddressSpace) -> Result<(), Error> { Ok(()) }

fn put_api_set_map(block: &mut [u8], off: usize) -> Result<(), Error> {
    const HEADER: usize = 28;
    const HASH: usize = 8;
    const ENTRY: usize = 24;
    const VALUE: usize = 20;
    let count = pe::apiset::entries().len();
    let hash_off = off + HEADER;
    let entry_off = hash_off + count * HASH;
    let value_off = entry_off + count * ENTRY;
    let mut text_off = value_off + count * VALUE;
    let mut names = Vec::new();
    for (index, &(name, target)) in pe::apiset::entries().iter().enumerate() {
        let name = utf16_bytes(name)?;
        let target = utf16_bytes(target)?;
        let name_at = text_off + names.len() * 2;
        names.extend_from_slice(&name[..name.len() - 1]);
        let target_at = text_off + names.len() * 2;
        names.extend_from_slice(&target[..target.len() - 1]);
        put_u32(block, entry_off + index * ENTRY + 4, (name_at - off) as u32);
        put_u32(block, entry_off + index * ENTRY + 8, ((name.len() - 1) * 2) as u32);
        put_u32(block, entry_off + index * ENTRY + 12, ((name.len() - 1) * 2) as u32);
        put_u32(block, entry_off + index * ENTRY + 16, (value_off + index * VALUE - off) as u32);
        put_u32(block, entry_off + index * ENTRY + 20, 1);
        put_u32(block, value_off + index * VALUE + 12, (target_at - off) as u32);
        put_u32(block, value_off + index * VALUE + 16, ((target.len() - 1) * 2) as u32);
    }
    text_off = text_off.checked_add(names.len() * 2).ok_or(Error::Einval)?;
    if text_off > block.len() { return Err(Error::Einval); }
    copy_u16(block, value_off + count * VALUE, &names);
    put_u32(block, off, 6);
    put_u32(block, off + 4, (text_off - off) as u32);
    put_u32(block, off + 12, count as u32);
    put_u32(block, off + 16, (entry_off - off) as u32);
    put_u32(block, off + 20, (hash_off - off) as u32);
    put_u32(block, off + 24, 31);
    for index in 0..count { put_u32(block, hash_off + index * HASH + 4, index as u32); }
    Ok(())
}


fn utf16(s: &str) -> Result<Vec<u16>, Error> {
    if s.contains('\0') { return Err(Error::Einval); }
    let mut v: Vec<u16> = s.encode_utf16().collect(); v.push(0); Ok(v)
}
fn utf16_bytes(s: &[u8]) -> Result<Vec<u16>, Error> {
    let text = core::str::from_utf8(s).map_err(|_| Error::Einval)?;
    utf16(text)
}
fn addr(base: u64, off: usize) -> Result<UserVirtAddr, Error> { UserVirtAddr::new(base.checked_add(off as u64).ok_or(Error::Einval)?).ok_or(Error::Einval) }
fn put_u32(b: &mut [u8], o: usize, v: u32) { b[o..o + 4].copy_from_slice(&v.to_le_bytes()); }
fn put_u16(b: &mut [u8], o: usize, v: u16) { b[o..o + 2].copy_from_slice(&v.to_le_bytes()); }
fn put_u64(b: &mut [u8], o: usize, v: u64) { b[o..o + 8].copy_from_slice(&v.to_le_bytes()); }
fn put_unicode(b: &mut [u8], o: usize, v: &[u16], ptr: u64) { let len = (v.len() - 1).saturating_mul(2) as u16; let max = v.len().saturating_mul(2) as u16; put_u16(b, o, len); put_u16(b, o + 2, max); put_u64(b, o + 8, ptr); }
fn put_unicode_with_capacity(b: &mut [u8], o: usize, v: &[u16], ptr: u64, capacity: usize) {
    let len = (v.len() - 1).saturating_mul(2) as u16;
    put_u16(b, o, len); put_u16(b, o + 2, capacity as u16); put_u64(b, o + 8, ptr);
}
fn copy_u16(b: &mut [u8], o: usize, v: &[u16]) { for (i, x) in v.iter().enumerate() { b[o + i * 2..o + i * 2 + 2].copy_from_slice(&x.to_le_bytes()); } }

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn arbitrary_ascii_process_strings_map_or_reject_without_partial_state(
            path in "[A-Za-z0-9_./\\\\]{0,128}", command in "[A-Za-z0-9 _.-]{0,128}") {
            let as_ = AddressSpace::new(0x40_000).unwrap();
            let result = build(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000,
                image_path: &path, command_line: &command, environment: &[("TEMP", "C:\\Temp")],
                process_id: 1, thread_id: 1 }, &as_);
            if let Ok(env) = result {
                prop_assert!(env.base.as_u64() % PAGE as u64 == 0);
                prop_assert!(env.peb.as_u64() >= env.base.as_u64());
                prop_assert!(env.tls.as_u64() < env.base.as_u64() + env.bytes as u64);
            } else {
                prop_assert_eq!(as_.vma_count(), 0);
            }
        }
    }
    #[test]
    fn maps_self_consistent_nt_environment() {
        let as_ = AddressSpace::new(0x10_000).unwrap();
        let e = build(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000, image_path: "C:\\notepad.exe", command_line: "notepad.exe file.txt", environment: &[("TEMP", "C:\\Temp"), ("PATH", "C:\\Windows")], process_id: 7, thread_id: 8 }, &as_).unwrap();
        assert!(e.peb.as_u64() >= e.base.as_u64() && e.teb.as_u64() < e.base.as_u64() + e.bytes as u64);
        assert_eq!(e.base.as_u64() % PAGE as u64, 0);
    }

    #[test]
    fn supplied_windows_process_parameters_are_encoded() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let e = build_with_modules_and_params(&EnvironmentInput {
            image_base: 0x1400_0000, image_size: 0x5000, image_path: "C:\\notepad.exe",
            command_line: "notepad.exe document.txt", environment: &[], process_id: 1, thread_id: 1,
        }, &[NtModuleInput { base: 0x1400_0000, entry: 0x1400_1000, size: 0x5000,
            full_name: "C:\\notepad.exe", base_name: "notepad.exe" }], &NtProcessParameters {
            current_directory: "C:\\Users\\oxide", current_directory_handle: 0x21, console_handle: 0x31,
            standard_handles: [0x41, 0x42, 0x43],
        }, &as_).unwrap();
        let vma = as_.find_vma(e.base).unwrap();
        let (bytes, off) = match vma.backing { VmaBacking::KernelBytes { data, off } => (data, off), _ => panic!("environment must be kernel bytes") };
        let at = |offset: usize| { let start = off + e.process_parameters.as_u64() as usize - e.base.as_u64() as usize + offset; u64::from_ne_bytes(bytes[start..start + 8].try_into().unwrap()) };
        assert_eq!(at(0x10), 0x31);
        assert_eq!(at(0x38), 0x21);
        assert_eq!([at(0x20), at(0x28), at(0x30)], [0x41, 0x42, 0x43]);
    }

    #[test]
    fn encoded_x64_fields_and_utf16_buffers_match_the_published_pointers() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let e = build(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000,
            image_path: "C:\\Windows\\notepad.exe", command_line: "notepad.exe a.txt",
            environment: &[("TEMP", "C:\\Temp")], process_id: 11, thread_id: 12 }, &as_).unwrap();
        let vma = as_.find_vma(e.base).unwrap();
        let (bytes, off) = match vma.backing { VmaBacking::KernelBytes { data, off } => (data, off), _ => panic!("environment must be immutable kernel bytes") };
        let read64 = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        let read16 = |o: usize| u16::from_le_bytes(bytes[o..o + 2].try_into().unwrap());
        let base = e.base.as_u64() as usize;
        assert_eq!(read64(0x10), 0x1400_0000);
        assert_eq!(read64(0x18), base as u64 + LDR_OFF as u64);
        assert_eq!(read64(0x20), base as u64 + PARAM_OFF as u64);
        assert_eq!(read64(TEB_OFF + 0x30), base as u64 + TEB_OFF as u64);
        assert_eq!(read64(TEB_OFF + 0x60), base as u64);
        assert_eq!(read64(TEB_OFF + 0x58), base as u64 + TLS_OFF as u64);
        assert_eq!(read64(TEB_OFF + TEB_ACTIVATION_CONTEXT_STACK_OFFSET),
            base as u64 + TEB_OFF as u64 + TEB_ACTIVATION_CONTEXT_STACK_INLINE as u64);
        assert_eq!(read64(TEB_OFF + TEB_SYSCALL_FRAME_OFFSET), base as u64 + PROCESS_SYSCALL_FRAME_OFF as u64);
        assert_eq!(read16(PARAM_OFF + 0x60), ("C:\\Windows\\notepad.exe".encode_utf16().count() * 2) as u16);
        assert_eq!(read16(PARAM_OFF + 0x70), ("notepad.exe a.txt".encode_utf16().count() * 2) as u16);
        assert_eq!(read64(PARAM_OFF + 0x80), base as u64 + ENV_OFF as u64);
        assert_eq!(read64(PEB_OFF + 0x68), base as u64 + API_SET_OFF as u64);
        assert_eq!(read64(PEB_OFF + PEB_PROCESS_HEAP_OFF), PROCESS_HEAP_HANDLE);
        assert_eq!(u32::from_le_bytes(bytes[PEB_OFF + PEB_NUMBER_OF_PROCESSORS_OFF..PEB_OFF + PEB_NUMBER_OF_PROCESSORS_OFF + 4].try_into().unwrap()), INITIAL_PROCESSOR_COUNT);
        assert_eq!(u32::from_le_bytes(bytes[API_SET_OFF..API_SET_OFF + 4].try_into().unwrap()), 6);
        assert_eq!(u32::from_le_bytes(bytes[API_SET_OFF + 12..API_SET_OFF + 16].try_into().unwrap()), pe::apiset::entries().len() as u32);
        assert_eq!(off, 0);
    }

    #[test]
    fn normalized_process_parameters_publish_sizes_consumed_by_environment_apis() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let e = build(&EnvironmentInput {
            image_base: 0x1400_0000, image_size: 0x5000,
            image_path: "C:\\Windows\\notepad.exe", command_line: "notepad.exe",
            environment: &[("TEMP", "C:\\Temp"), ("PATH", "C:\\Windows")],
            process_id: 1, thread_id: 2,
        }, &as_).unwrap();
        let vma = as_.find_vma(e.base).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
        let read32 = |offset: usize| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let read64 = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        assert_eq!(read32(PARAM_OFF), PARAM_SIZE);
        assert_eq!(read32(PARAM_OFF + 4), PARAM_SIZE);
        assert_eq!(read32(PARAM_OFF + 8), PARAM_FLAGS_NORMALIZED);
        assert_eq!(read64(PARAM_OFF + PARAM_ENVIRONMENT_SIZE_OFF), "TEMP=C:\\Temp\0PATH=C:\\Windows\0\0".encode_utf16().count() as u64 * 2);
        assert_eq!(read64(PARAM_OFF + 0x80), e.base.as_u64() + ENV_OFF as u64);
        assert_eq!(read64(PARAM_OFF + 0x80) - e.base.as_u64() - PARAM_OFF as u64, PARAM_SIZE as u64);
    }

    #[test]
    fn loader_lists_publish_the_executable_and_ntdll_as_circular_entries() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let e = build_with_modules(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000,
            image_path: "C:\\Windows\\notepad.exe", command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 1 }, &[
            NtModuleInput { base: 0x1400_0000, entry: 0x1400_1010, size: 0x5000, full_name: "C:\\Windows\\notepad.exe", base_name: "notepad.exe" },
            NtModuleInput { base: 0x7000_0000, entry: 0, size: 0x9000, full_name: "C:\\Windows\\System32\\ntdll.dll", base_name: "ntdll.dll" },
        ], &as_).unwrap();
        let vma = as_.find_vma(e.base).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
        let read64 = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        let first = e.base.as_u64() + MOD_OFF as u64;
        let second = first + MOD_STRIDE as u64;
        assert_eq!(read64(LDR_OFF + 0x10), first);
        assert_eq!(read64(LDR_OFF + 0x18), second);
        assert_eq!(read64(MOD_OFF + 0x30), 0x1400_0000);
        assert_eq!(read64(MOD_OFF + 0x38), 0x1400_1010);
        assert_eq!(read64(MOD_OFF + MOD_STRIDE + 0x30), 0x7000_0000);
        assert_eq!(read64(MOD_OFF + MOD_STRIDE + 0x38), 0);
        assert_eq!(read64(MOD_OFF), second);
        assert_eq!(read64(MOD_OFF + 8), e.base.as_u64() + LDR_OFF as u64 + 0x18);
        assert_eq!(read64(MOD_OFF + MOD_STRIDE), e.base.as_u64() + LDR_OFF as u64 + 0x10);
        assert_eq!(read64(MOD_OFF + MOD_STRIDE + 8), first);
    }

    #[test]
    fn loader_records_remain_intact_when_the_module_list_reaches_the_string_arena() {
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let mut modules = Vec::new();
        for index in 0..16 {
            modules.push(NtModuleInput { base: 0x7000_0000 + index * 0x10_000, entry: 0, size: 0x9000,
                full_name: "C:\\Windows\\System32\\module.dll", base_name: "module.dll" });
        }
        let e = build_with_modules(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000,
            image_path: "C:\\Windows\\notepad.exe", command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 1 }, &modules, &as_).unwrap();
        let vma = as_.find_vma(e.base).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
        for (index, module) in modules.iter().enumerate() {
            let offset = MOD_OFF + index * MOD_STRIDE + 0x30;
            assert_eq!(u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()), module.base);
        }
    }
    #[test]
    fn rejects_embedded_nul_without_mapping() {
        let as_ = AddressSpace::new(0x10_000).unwrap();
        assert_eq!(build(&EnvironmentInput { image_base: 1, image_size: 1, image_path: "bad\0path", command_line: "", environment: &[], process_id: 1, thread_id: 1 }, &as_), Err(Error::Einval));
        assert_eq!(as_.vma_count(), 0);
    }

    #[test]
    fn rejects_oversized_strings_before_mapping_any_bytes() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let path = "x".repeat(BLOCK_BYTES);
        let result = build(&EnvironmentInput { image_base: 1, image_size: 1,
            image_path: &path, command_line: "", environment: &[], process_id: 1, thread_id: 1 }, &as_);
        assert_eq!(result, Err(Error::Einval));
        assert_eq!(as_.vma_count(), 0);
    }

    #[test]
    fn thread_teb_is_distinct_and_publishes_thread_identity() {
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let first = build_thread_teb(7, 8, 0x12_000, &as_).unwrap();
        let second = build_thread_teb(7, 9, 0x12_000, &as_).unwrap();
        assert_ne!(first, second);
        let vma = as_.find_vma(first).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("TEB must be kernel-backed") };
        assert_eq!(u64::from_le_bytes(data[0x30..0x38].try_into().unwrap()), first.as_u64());
        assert_eq!(u64::from_le_bytes(data[0x60..0x68].try_into().unwrap()), 0x12_000);
        assert_eq!(u32::from_le_bytes(data[0x40..0x44].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(data[0x48..0x4c].try_into().unwrap()), 8);
        assert_eq!(u64::from_le_bytes(data[0x58..0x60].try_into().unwrap()), first.as_u64() + 0x180);
        assert_eq!(u64::from_le_bytes(data[TEB_ACTIVATION_CONTEXT_STACK_OFFSET..TEB_ACTIVATION_CONTEXT_STACK_OFFSET + 8].try_into().unwrap()),
            first.as_u64() + TEB_ACTIVATION_CONTEXT_STACK_INLINE as u64);
        assert_eq!(u32::from_le_bytes(data[TEB_CURRENT_LOCALE_OFF..TEB_CURRENT_LOCALE_OFF + 4].try_into().unwrap()), 0x409);
        assert!(data[TEB_TLS_SLOTS_OFF..TEB_TLS_SLOTS_OFF + TEB_TLS_SLOTS * 8].iter().all(|byte| *byte == 0));
        assert_eq!(u64::from_le_bytes(data[TEB_TLS_EXPANSION_SLOTS_OFF..TEB_TLS_EXPANSION_SLOTS_OFF + 8].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(data[TEB_SYSCALL_FRAME_OFFSET..TEB_SYSCALL_FRAME_OFFSET + 8].try_into().unwrap()), first.as_u64() + THREAD_SYSCALL_FRAME_OFF as u64);
    }

    #[test]
    fn process_teb_publishes_native_tls_layout_and_reserved_bitmap_bits() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let e = build(&EnvironmentInput { image_base: 0x1400_0000, image_size: 0x5000,
            image_path: "C:\\Windows\\notepad.exe", command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 2 }, &as_).unwrap();
        let vma = as_.find_vma(e.base).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
        let read32 = |offset: usize| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let read64 = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        assert_eq!(read32(PEB_OFF + 0x80), 0x0001_0001);
        assert_eq!(read32(PEB_OFF + 0x84), 0);
        assert_eq!(read64(PEB_OFF + 0x78), e.base.as_u64() + TLS_BITMAP_DESC_OFF as u64);
        assert!(data[PEB_OFF + 0x240..PEB_OFF + 0x2c0].iter().all(|byte| *byte == 0));
        assert_eq!(read64(PEB_OFF + 0x238), e.base.as_u64() + TLS_EXP_BITMAP_DESC_OFF as u64);
        assert_eq!(read32(TLS_BITMAP_DESC_OFF), 64);
        assert_eq!(read32(TLS_EXP_BITMAP_DESC_OFF), 1024);
        assert_eq!(read64(TLS_BITMAP_DESC_OFF + 8), e.base.as_u64() + PEB_OFF as u64 + 0x80);
        assert_eq!(read64(TLS_EXP_BITMAP_DESC_OFF + 8), e.base.as_u64() + PEB_OFF as u64 + 0x240);
        assert_eq!(read32(TEB_OFF + TEB_CURRENT_LOCALE_OFF), 0x409);
        assert_eq!(read64(TEB_OFF + TEB_TLS_EXPANSION_SLOTS_OFF), 0);
    }

    #[test]
    fn process_teb_publishes_the_actual_exec_stack_nt_tib_bounds() {
        let as_ = AddressSpace::new(0x40_000).unwrap();
        let stack = as_.mmap(None, 0x8000, VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE, VmaBacking::Anonymous, false).unwrap();
        let stack_top = stack.as_u64() + 0x8000;
        let e = build_with_modules_and_stack(&EnvironmentInput {
            image_base: 0x1400_0000, image_size: 0x5000, image_path: "C:\\Windows\\notepad.exe",
            command_line: "notepad.exe", environment: &[], process_id: 1, thread_id: 2,
        }, &[NtModuleInput { base: 0x1400_0000, entry: 0x1400_1000, size: 0x5000,
            full_name: "C:\\Windows\\notepad.exe", base_name: "notepad.exe" }], 0, stack_top, &as_).unwrap();
        let vma = as_.find_vma(e.base).unwrap();
        let data = match vma.backing { VmaBacking::KernelBytes { data, .. } => data, _ => panic!("environment must be kernel-backed") };
        let read64 = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        assert_eq!(read64(TEB_OFF + TEB_STACK_BASE_OFF), stack_top);
        assert_eq!(read64(TEB_OFF + TEB_STACK_LIMIT_OFF), stack.as_u64());
        assert_eq!(read64(TEB_OFF + TEB_DEALLOCATION_STACK_OFF), stack.as_u64());
    }
}
