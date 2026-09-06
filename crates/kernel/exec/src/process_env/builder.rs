use alloc::{string::String, vec, vec::Vec};
use hal::UserVirtAddr;
use pe::Error;
use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};

use super::layout::*;

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

/// Validate the inherited standard-handle tuple before it is published in
/// the x64 process-parameter block. A console process receives either no
/// standard handles or the complete input/output/error triplet; a partial
/// tuple would make `GetStdHandle` expose stale, non-inherited state.
/// # C: O(1)
pub fn standard_handle_slots(handles: [u64; 3]) -> Option<[u64; 3]> {
    let present = handles.map(|handle| handle != 0);
    if present.iter().all(|value| !value) || present.iter().all(|value| *value) { Some(handles) } else { None }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtModuleInput<'a> {
    pub base: u64,
    pub entry: u64,
    pub size: u32,
    pub full_name: &'a str,
    pub base_name: &'a str,
}

/// Validated x64 `UNICODE_STRING` metadata for a process-parameter string.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct X64ProcessParameterString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: u64,
}

/// Validate and encode one normalized process-parameter string.
///
/// The returned UTF-16 vector includes its terminating WCHAR. Descriptor
/// lengths are byte counts: `length` excludes that terminator and
/// `maximum_length` is the supplied storage capacity. The same contract is
/// used for `CURDIR.DosPath` and `CommandLine` in the native x64 layout.
/// # C: O(value length)
pub fn encode_x64_process_parameter_string(value: &str, buffer: u64, capacity_bytes: usize) -> Result<(X64ProcessParameterString, Vec<u16>), Error> {
    if buffer & 1 != 0 || capacity_bytes == 0 || capacity_bytes & 1 != 0 || capacity_bytes > u16::MAX as usize { return Err(Error::Einval); }
    let encoded = utf16(value)?;
    let length_bytes = encoded.len().checked_sub(1).and_then(|n| n.checked_mul(2)).ok_or(Error::Einval)?;
    let required = length_bytes.checked_add(2).ok_or(Error::Einval)?;
    if required > capacity_bytes || length_bytes > u16::MAX as usize { return Err(Error::Einval); }
    Ok((X64ProcessParameterString { length: length_bytes as u16, maximum_length: capacity_bytes as u16, buffer }, encoded))
}

/// Build and map the initial PEB/TEB/process-parameters block.
/// # C: O(image_path + command_line + environment)
pub fn build(input: &EnvironmentInput<'_>, as_: &AddressSpace) -> Result<NtProcessEnvironment, Error> {
    let base_name = input.image_path.rsplit(['\\', '/']).next().unwrap_or(input.image_path);
    let module = NtModuleInput { base: input.image_base, entry: input.image_base, size: input.image_size, full_name: input.image_path, base_name };
    build_with_modules(input, core::slice::from_ref(&module), as_)
}

/// Allocate the thread-local NT arena for a thread created after process
/// exec. The PEB remains process-owned; this arena is
/// thread-owned and carries the TEB self pointer, IDs, PEB pointer, and TLS.
/// # C: O(1)
pub fn build_thread_teb(process_id: u32, thread_id: u32, peb: u64, as_: &AddressSpace) -> Result<UserVirtAddr, Error> {
    build_thread_teb_with_stack(process_id, thread_id, peb, 0, 0, as_)
}

/// Allocate one thread-owned TEB and publish its NT_TIB stack bounds.
/// `stack_limit` is the low address and `stack_base` is the exclusive high
/// address. Zero bounds are accepted only for environment fixtures that have
/// no stack mapping; a live NT thread must supply both bounds.
/// # C: O(1)
pub fn build_thread_teb_with_stack(process_id: u32, thread_id: u32, peb: u64,
    stack_limit: u64, stack_base: u64, as_: &AddressSpace) -> Result<UserVirtAddr, Error> {
    if (stack_limit == 0) != (stack_base == 0)
        || (stack_limit != 0 && stack_limit >= stack_base) { return Err(Error::Einval); }
    let reservation = as_.mmap(None, THREAD_TEB_BYTES, VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE, VmaBacking::Anonymous, false).map_err(|_| Error::Einval)?;
    let base = reservation.as_u64();
    let mut teb = vec![0u8; THREAD_TEB_BYTES];
    put_u64(&mut teb, 0x30, base);
    put_u64(&mut teb, 0x60, peb);
    put_u32(&mut teb, 0x40, process_id);
    put_u32(&mut teb, 0x48, thread_id);
    put_u64(&mut teb, 0x58, base + THREAD_TLS_OFF as u64);
    put_u64(&mut teb, TEB_STACK_BASE_OFF, stack_base);
    put_u64(&mut teb, TEB_STACK_LIMIT_OFF, stack_limit);
    put_u64(&mut teb, TEB_DEALLOCATION_STACK_OFF, stack_limit);
    put_u64(&mut teb, TEB_ACTIVATION_CONTEXT_STACK_OFFSET,
        base + TEB_ACTIVATION_CONTEXT_STACK_INLINE as u64);
    init_activation_list(&mut teb, 0, base);
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

/// Remove exactly one TEB mapping produced by this module.
/// # C: O(1)
pub fn unmap_thread_teb(teb: UserVirtAddr, as_: &AddressSpace) -> bool {
    let Some(vma) = as_.find_vma(teb) else { return false; };
    if vma.start != teb || vma.end.as_u64().checked_sub(teb.as_u64()) != Some(THREAD_TEB_BYTES as u64) {
        return false;
    }
    crate::nt_unmap::unmap_range(as_, teb, THREAD_TEB_BYTES).is_ok()
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
    let standard_handles = standard_handle_slots(params.standard_handles).ok_or(Error::Einval)?;
    let image_path = utf16(input.image_path)?;
    let command_line = utf16(input.command_line)?;
    let mut env = Vec::new();
    for &(name, value) in input.environment {
        if name.contains('\0') || value.contains('\0') { return Err(Error::Einval); }
        env.extend(utf16(&(String::from(name) + "=" + value))?);
    }
    // The Windows environment block is terminated by two WCHAR NULs: one
    // terminates the final `NAME=VALUE` string and one terminates the block.
    // `utf16` already supplies the first terminator for non-empty input; an
    // empty environment still needs both explicitly.
    env.push(0);
    if env.len() == 1 { env.push(0); }
    let mut strings = Vec::new();
    strings.extend_from_slice(&image_path);
    let image_path_off = PROCESS_STR_OFF;
    let command_off = PROCESS_STR_OFF + strings.len() * 2;
    strings.extend_from_slice(&command_line);
    let current_dir = utf16(params.current_directory)?;
    let current_dir_off = PROCESS_STR_OFF + strings.len() * 2;
    strings.extend_from_slice(&current_dir);
    let mut module_offsets = Vec::new();
    let mut module_text_off = STR_OFF;
    for module in modules {
        let full = utf16(module.full_name)?;
        let base = utf16(module.base_name)?;
        module_offsets.push((module_text_off, full.len(), module_text_off + full.len() * 2, base.len()));
        module_text_off = module_text_off.checked_add((full.len() + base.len()) * 2).ok_or(Error::Einval)?;
    }
    let env_off = ENV_OFF;
    let total = env_off.checked_add(env.len() * 2).ok_or(Error::Einval)?;
    if total > ENV_OFF + ENV_BYTES || module_text_off > ENV_OFF
        || current_dir_off.checked_add(CURRENT_DIR_STORAGE).ok_or(Error::Einval)? > LDR_OFF { return Err(Error::Einval); }
    // Validate both native descriptors before reserving an address-space
    // range. The final pass below only substitutes the published buffer
    // addresses, so malformed input cannot leave a reservation behind.
    let command_capacity = command_line.len().checked_mul(2).ok_or(Error::Einval)?;
    let _ = encode_x64_process_parameter_string(input.command_line, 2, command_capacity)?;
    let _ = encode_x64_process_parameter_string(params.current_directory, 2, CURRENT_DIR_STORAGE)?;
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
    // Normalized parameters own one page; strings and environment have
    // separate extents. EnvironmentSize includes its terminating WCHAR.
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
    init_activation_list(&mut block, TEB_OFF, base + TEB_OFF as u64);
    put_u32(&mut block, TEB_OFF + TEB_CURRENT_LOCALE_OFF, 0x409);
    put_u64(&mut block, TEB_OFF + TEB_DEALLOCATION_STACK_OFF, stack_base);
    // The fixed TEB block contains all 64 native TLS slots inline.  The
    // expansion pointer stays NULL until a slot >= 64 is requested, matching
    // kernelbase's TlsAlloc/TlsSetValue behavior.
    put_u64(&mut block, TEB_OFF + TEB_SYSCALL_FRAME_OFFSET, base + PROCESS_SYSCALL_FRAME_OFF as u64);
    put_u64(&mut block, PARAM_OFF + 0x10, params.console_handle);
    // Wine's initial parameter builder publishes a normal-show startup
    // disposition and uses the executable path as the default window title.
    // Keep the title backed by the one canonical image-path string.
    put_u32(&mut block, PARAM_OFF + PARAM_SHOW_WINDOW_OFF, SHOW_WINDOW_NORMAL);
    put_u32(&mut block, PARAM_OFF + PARAM_PROCESS_GROUP_ID_OFF, input.process_id);
    put_u64(&mut block, PARAM_OFF + PARAM_CURRENT_DIRECTORY_HANDLE_OFF, params.current_directory_handle);
    for (offset, handle) in [0x20usize, 0x28, 0x30].into_iter().zip(standard_handles) {
        put_u64(&mut block, PARAM_OFF + offset, handle);
    }
    put_unicode(&mut block, PARAM_OFF + 0x60, &image_path, base + image_path_off as u64);
    let (command_desc, command_line) = encode_x64_process_parameter_string(input.command_line,
        base + command_off as u64, command_capacity)?;
    let (current_dir_desc, current_dir) = encode_x64_process_parameter_string(params.current_directory,
        base + current_dir_off as u64, CURRENT_DIR_STORAGE)?;
    put_x64_unicode(&mut block, PARAM_OFF + PARAM_COMMAND_LINE_OFF, command_desc);
    put_x64_unicode(&mut block, PARAM_OFF + PARAM_CURRENT_DIRECTORY_OFF, current_dir_desc);
    put_unicode(&mut block, PARAM_OFF + PARAM_WINDOW_TITLE_OFF, &image_path, base + image_path_off as u64);
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
    // The published current-frame pointer addresses the final page of the
    // thread arena, disjoint from inline TEB, module TLS and debug storage.
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
fn put_x64_unicode(b: &mut [u8], o: usize, desc: X64ProcessParameterString) {
    put_u16(b, o, desc.length); put_u16(b, o + 2, desc.maximum_length); put_u64(b, o + 8, desc.buffer);
}
fn copy_u16(b: &mut [u8], o: usize, v: &[u16]) { for (i, x) in v.iter().enumerate() { b[o + i * 2..o + i * 2 + 2].copy_from_slice(&x.to_le_bytes()); } }

fn init_activation_list(block: &mut [u8], teb_off: usize, teb_address: u64) {
    let offset = TEB_ACTIVATION_CONTEXT_STACK_INLINE + ACTIVATION_LIST_OFF;
    let address = teb_address + offset as u64;
    put_u64(block, teb_off + offset, address);
    put_u64(block, teb_off + offset + POINTER_BYTES, address);
}


#[cfg(test)]
#[path = "tests/existing.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/arena.rs"]
mod arena_tests;
