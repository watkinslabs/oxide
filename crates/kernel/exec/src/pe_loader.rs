#[path = "pe_loader/ntdll_catalog.rs"]
pub mod ntdll_catalog;
use ntdll_catalog::NTDLL_EXPORTS;
use alloc::sync::Arc; use crate::pe_init; use crate::pe_modules; use crate::process_env; use hal::UserVirtAddr; use pe::{self, SectionFlags}; use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeLoadedImage {
    pub base: u64,
    pub preferred_base: u64,
    pub entry: UserVirtAddr,
    pub size: u32,
    pub exception_directory: (u32, u32),
    pub tls_directory: (u32, u32),
}
pub struct PeLoadedModule<'a> {
    pub name: &'a [u8],
    pub image: PeLoadedImage,
}
pub struct PeModuleBase<'a> {
    pub name: &'a [u8],
    pub base: u64, pub size: u32,
}
pub struct NtRuntime {
    pub base: UserVirtAddr,
    pub bytes: usize,
    pub relay_call: u64,
    pub wine_dispatcher: u64,
    pub wine_unix_dispatcher: u64,
    pub wine_unixlib_handle: u64,
    addresses: [u64; 552],
}
/// Index of the stack probe, whose entry is machine code rather than a trap.
const CHKSTK_INDEX: usize = 550;
/// Index of the language-specific handler, likewise machine code.
const C_SPECIFIC_HANDLER_INDEX: usize = 551;
/// Index of the unwind entry the language-specific handler tail-calls.
const RTL_UNWIND_EX_INDEX: usize = 201;
/// Index of the debugger breakpoint entry. The ABI is a user-mode routine that
/// executes a breakpoint instruction, so exception dispatch owns the result;
/// encoding it as a service trap ran an unrelated service on junk registers.
const DBG_BREAK_POINT_INDEX: usize = 220;
const WINE_SYSCALL_DISPATCHER: &[u8] = b"__wine_syscall_dispatcher";
fn runtime_stub_bytes(index: usize) -> usize {
    if index == DBG_BREAK_POINT_INDEX { pe::nt_stub::X64_BREAKPOINT_STUB_BYTES }
    else if index == CHKSTK_INDEX { pe::nt_stub::X64_RET_STUB_BYTES }
    else if index == C_SPECIFIC_HANDLER_INDEX { pe::nt_stub::X64_C_SPECIFIC_HANDLER_BYTES }
    else if index == 505 { pe::nt_stub::X64_ZERO_ARG_STUB_BYTES }
    else if matches!(index, 6 | 242 | 435 | 436 | 437 | 483 | 507 | 509 | 510 | 511) { pe::nt_stub::X64_UNARY_STUB_BYTES } else { pe::nt_stub::X64_SIX_ARG_STUB_BYTES }
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeEntryState {
    pub rip: UserVirtAddr,
    pub rsp: UserVirtAddr,
    pub gs_base: UserVirtAddr,
    pub personality: ExecutionPersonality,
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExecutionPersonality { Linux, Nt }
#[derive(Debug)]
pub struct PeProcess {
    pub image: PeLoadedImage,
    pub environment: process_env::NtProcessEnvironment,
    pub entry: PeEntryState,
    pub startup: crate::pe_startup::PeStartupTransaction,
    pub initializers: alloc::vec::Vec<PeModuleInitializer>,
    pub initializer_trampoline: Option<pe_init::PeInitTrampoline>,
}
/// One dependency DLL initializer the runtime must call before application startup.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PeInitializerKind { TlsCallback, DllEntry }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeModuleInitializer { pub base: u64, pub entry: UserVirtAddr, pub kind: PeInitializerKind }

struct PeImageTransaction<'a> {
    as_: &'a AddressSpace,
    base: UserVirtAddr,
    bytes: usize,
    committed: bool,
}

impl PeImageTransaction<'_> {
    fn new(as_: &AddressSpace, base: UserVirtAddr, bytes: usize) -> PeImageTransaction<'_> {
        PeImageTransaction { as_, base, bytes, committed: false }
    }
    fn commit(&mut self) { self.committed = true; }
}

impl Drop for PeImageTransaction<'_> {
    fn drop(&mut self) {
        if !self.committed { let _ = self.as_.munmap(self.base, self.bytes); }
    }
}

fn executable_entry(as_: &AddressSpace, entry: UserVirtAddr) -> bool {
    as_.find_vma(entry).is_some_and(|vma| vma.prot.contains(VmaProt::EXEC))
}

pub trait ImportResolver {
    fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error>;
}
pub struct PeExportModule<'a> {
    pub name: &'a [u8],
    pub image: pe::Image<'a>,
    pub base: u64,
}
pub struct PeExportResolver<'a> {
    pub modules: &'a [PeExportModule<'a>],
}
pub struct PeExportRef<'m, 'b> {
    pub name: &'b [u8],
    pub image: &'m pe::Image<'b>,
    pub base: u64,
}
pub struct PeGraphResolver<'m, 'b, R> {
    pub modules: &'m [PeExportRef<'m, 'b>],
    pub fallback: &'m R,
}
impl ImportResolver for PeExportResolver<'_> {
    fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
        let module = self.modules.iter().find(|module| ascii_eq_ignore_case(module.name, dll)).ok_or(pe::Error::Unsupported)?;
        let rva = module.image.executable_export_rva(import)?.ok_or(pe::Error::Unsupported)?;
        module.base.checked_add(rva as u64).ok_or(pe::Error::Einval)
    }
}
impl<R: ImportResolver> ImportResolver for PeGraphResolver<'_, '_, R> {
    fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
        self.resolve_graph(dll, import, 0)
    }
}
impl<'m, 'b, R: ImportResolver> PeGraphResolver<'m, 'b, R> {
    fn resolve_graph(&self, dll: &[u8], import: &pe::ImportThunk<'_>, depth: u8) -> Result<u64, pe::Error> {
        if depth >= 16 { return Err(pe::Error::Unsupported); }
        if ascii_eq_ignore_case(dll, b"ntdll.dll") {
            if let Ok(address) = self.fallback.resolve(dll, import) { return Ok(address); }
        }
        if let Some(target) = pe::apiset::target(dll) {
            return self.resolve_graph(target, import, depth + 1);
        }
        if let Some(module) = self.modules.iter().find(|module| ascii_eq_ignore_case(module.name, dll)) {
            let target = module.image.export_target(import)?.ok_or(pe::Error::Unsupported)?;
            return match target {
                pe::ExportTarget::Rva(_) => module.image.executable_export_rva(import)?.and_then(|rva| module.base.checked_add(rva as u64)).ok_or(pe::Error::Unsupported),
                pe::ExportTarget::Forwarder(forwarder) => {
                    let dot = forwarder.iter().position(|byte| *byte == b'.').ok_or(pe::Error::Einval)?;
                    if dot == 0 || dot + 1 >= forwarder.len() { return Err(pe::Error::Einval); }
                    let mut forwarded_dll = [0u8; 256];
                    let mut dll_len = dot.min(forwarded_dll.len());
                    forwarded_dll[..dll_len].copy_from_slice(&forwarder[..dll_len]);
                    if dll_len < 4 || !ascii_eq_ignore_case(&forwarded_dll[dll_len - 4..dll_len], b".dll") {
                        if dll_len + 4 > forwarded_dll.len() { return Err(pe::Error::Einval); }
                        forwarded_dll[dll_len..dll_len + 4].copy_from_slice(b".dll"); dll_len += 4;
                    }
                    let symbol = &forwarder[dot + 1..];
                    let forwarded = if symbol.first() == Some(&b'#') {
                        let mut ordinal = 0u32;
                        for byte in &symbol[1..] { if !byte.is_ascii_digit() { return Err(pe::Error::Einval); } ordinal = ordinal.checked_mul(10).and_then(|n| n.checked_add((byte - b'0') as u32)).ok_or(pe::Error::Einval)?; }
                        pe::ImportThunk::Ordinal(u16::try_from(ordinal).map_err(|_| pe::Error::Einval)?)
                    } else { pe::ImportThunk::Name { hint: 0, name: symbol } };
                    self.resolve_graph(&forwarded_dll[..dll_len], &forwarded, depth + 1)
                }
            };
        }
        self.fallback.resolve(dll, import)
    }
}
impl ImportResolver for NtRuntime {
    fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
        if !ascii_eq_ignore_case(dll, b"ntdll.dll") { return Err(pe::Error::Unsupported); }
        let pe::ImportThunk::Name { name, .. } = import else { return Err(pe::Error::Unsupported); };
        for (index, export) in NTDLL_EXPORTS.iter().enumerate() {
            if *name == *export { return Ok(self.addresses[index]); }
        }
        Err(pe::Error::Unsupported)
    }
}

/// Resolve one export from the kernel-provided synthetic ntdll page.
/// The page is executable stubs rather than a PE image, so its export table
/// is owned by this runtime catalog instead of being read from user memory.
pub fn resolve_nt_runtime_export(base: u64, name: &[u8]) -> Option<u64> {
    let mut offset = 0u64;
    for (index, export) in NTDLL_EXPORTS.iter().enumerate() {
        if *export == name { return base.checked_add(offset); }
        offset = offset.checked_add(runtime_stub_bytes(index) as u64)?;
    }
    None
}

/// Resolve the private synchronous window-procedure continuation.
pub fn resolve_nt_runtime_wndproc_continuation(base: u64) -> Option<u64> {
    let mut offset = 0u64;
    for (index, _) in NTDLL_EXPORTS.iter().enumerate() { offset = offset.checked_add(runtime_stub_bytes(index) as u64)?; }
    offset = offset.checked_add(pe::nt_stub::encode_x64_run_once_continuation(syscall::nt::NtService::RtlRunOnceComplete.entry()).len() as u64)?;
    base.checked_add(offset)
}

/// Resolve the private native APC return leg in the synthetic ntdll page.
pub fn resolve_nt_runtime_apc_continuation(base: u64) -> Option<u64> {
    let mut offset = 0u64;
    for (index, _) in NTDLL_EXPORTS.iter().enumerate() { offset = offset.checked_add(runtime_stub_bytes(index) as u64)?; }
    offset = offset.checked_add(pe::nt_stub::encode_x64_run_once_continuation(syscall::nt::NtService::RtlRunOnceComplete.entry()).len() as u64)?;
    offset = offset.checked_add(pe::nt_stub::encode_x64_wndproc_continuation(syscall::nt::NtService::CallbackReturn.entry()).len() as u64)?;
    base.checked_add(offset)
}

/// Resolve the address of a runtime-owned exported entry.
/// # C: O(1)
pub fn resolve_nt_runtime_data_export(base: u64, name: &[u8]) -> Option<u64> {
    if name != WINE_SYSCALL_DISPATCHER && name != b"__wine_unix_call_dispatcher" && name != b"__wine_unixlib_handle" { return None; }
    let mut offset = 0u64;
    for (index, _) in NTDLL_EXPORTS.iter().enumerate() { offset = offset.checked_add(runtime_stub_bytes(index) as u64)?; }
    let continuation = pe::nt_stub::encode_x64_run_once_continuation(syscall::nt::NtService::RtlRunOnceComplete.entry());
    let wndproc_continuation = pe::nt_stub::encode_x64_wndproc_continuation(syscall::nt::NtService::CallbackReturn.entry());
    let apc_continuation = pe::nt_stub::encode_x64_apc_continuation();
    // Wine declares these three symbols as data. Its unix_lib initializer
    // obtains the symbol address, then loads the dispatcher pointer from that
    // slot before jumping. Keep the slot identity distinct from the code
    // entry; returning the code address makes Wine interpret instruction bytes
    // as a function pointer.
    let data_offset = offset.checked_add(continuation.len() as u64)?.checked_add(wndproc_continuation.len() as u64)?
        .checked_add(apc_continuation.len() as u64)?;
    let target = if name == WINE_SYSCALL_DISPATCHER { data_offset }
        else if name == b"__wine_unix_call_dispatcher" { data_offset.checked_add(8)? }
        else { data_offset.checked_add(16)? };
    base.checked_add(target)
}
pub fn map_nt_runtime(as_: &AddressSpace) -> Result<NtRuntime, pe::Error> {
    let page = hal::PAGE_SIZE_BYTES as usize;
    let continuation = pe::nt_stub::encode_x64_run_once_continuation(syscall::nt::NtService::RtlRunOnceComplete.entry());
    let stub_bytes: usize = NTDLL_EXPORTS.iter().enumerate().map(|(index, _)| runtime_stub_bytes(index)).sum();
    let wine_dispatcher = pe::nt_stub::encode_x64_wine_dispatcher_stub(syscall::nt::NtService::WineSyscall.entry());
    let wine_unix_dispatcher = pe::nt_stub::encode_x64_unix_call_dispatcher_stub(syscall::nt::NtService::WineUnixCall.entry());
    let wndproc_continuation = pe::nt_stub::encode_x64_wndproc_continuation(syscall::nt::NtService::CallbackReturn.entry());
    let apc_continuation = pe::nt_stub::encode_x64_apc_continuation();
    let code_bytes = stub_bytes + continuation.len() + wndproc_continuation.len() + apc_continuation.len() + 24 + pe::nt_stub::X64_RELAY_STUB_BYTES + wine_dispatcher.len() + wine_unix_dispatcher.len() + 8
        + syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT * core::mem::size_of::<u64>();
    let mapped_bytes = (code_bytes + page - 1) / page * page;
    let arena = as_.get_unmapped_area(mapped_bytes).map_err(|_| pe::Error::Einval)?.as_u64();
    let base_address = UserVirtAddr::new(arena).ok_or(pe::Error::Einval)?;
    let mut code = alloc::vec![0u8; mapped_bytes];
    let mut addresses = [0u64; 552];
    let mut offset = 0usize;
    for index in 0..NTDLL_EXPORTS.len() {
        // Keep the debug exports tied to their actual catalog indexes. This
        // block predates the generated selector table and is the one place
        // where the handwritten table differs from the export array.
        let selector = ntdll_catalog::service_for_index(index).unwrap_or(syscall::nt::NtService::FreeHeap);
        let bytes = if index == DBG_BREAK_POINT_INDEX { pe::nt_stub::encode_x64_breakpoint_stub().to_vec() }
            else if index == CHKSTK_INDEX { pe::nt_stub::encode_x64_ret_stub().to_vec() }
            else if index == C_SPECIFIC_HANDLER_INDEX {
                // The handler enters the unwind entry, which precedes it on
                // the page, so its address is already assigned.
                let unwind = arena.checked_add(addresses[RTL_UNWIND_EX_INDEX]).ok_or(pe::Error::Einval)?;
                pe::nt_stub::encode_x64_c_specific_handler(unwind).to_vec()
            }
            else if index == 505 { pe::nt_stub::encode_x64_zero_arg_stub(selector.entry()).to_vec() }
            else if matches!(index, 6 | 242 | 435 | 436 | 437 | 483 | 507 | 509 | 510 | 511) { pe::nt_stub::encode_x64_unary_stub(selector.entry()).to_vec() }
            else { pe::nt_stub::encode_x64_six_arg_stub(selector.entry()).to_vec() };
        if offset.checked_add(bytes.len()).filter(|&end| end <= code.len()).is_none() { return Err(pe::Error::Einval); }
        code[offset..offset + bytes.len()].copy_from_slice(&bytes);
        addresses[index] = offset as u64;
        debug_assert_eq!(bytes.len(), runtime_stub_bytes(index));
        offset += bytes.len();
    }
    code[offset..offset + continuation.len()].copy_from_slice(&continuation);
    offset += continuation.len();
    code[offset..offset + wndproc_continuation.len()].copy_from_slice(&wndproc_continuation);
    offset += wndproc_continuation.len();
    code[offset..offset + apc_continuation.len()].copy_from_slice(&apc_continuation);
    let data_offset = offset + apc_continuation.len();
    let relay_offset = data_offset + 24;
    let relay = pe::nt_stub::encode_x64_relay_stub(syscall::nt::NtService::RelayCall.entry());
    code[relay_offset..relay_offset + relay.len()].copy_from_slice(&relay);
    let dispatcher_offset = relay_offset + relay.len();
    code[dispatcher_offset..dispatcher_offset + wine_dispatcher.len()].copy_from_slice(&wine_dispatcher);
    let unix_dispatcher_offset = dispatcher_offset + wine_dispatcher.len();
    code[unix_dispatcher_offset..unix_dispatcher_offset + wine_unix_dispatcher.len()].copy_from_slice(&wine_unix_dispatcher);
    let handle_offset = unix_dispatcher_offset + wine_unix_dispatcher.len();
    code[handle_offset..handle_offset + 8].copy_from_slice(&syscall::nt::WINE_UNIXLIB_HANDLE.to_le_bytes());
    let table_offset = handle_offset + 8;
    let dispatcher = arena.checked_add(dispatcher_offset as u64).ok_or(pe::Error::Einval)?;
    let unix_callable = arena.checked_add(unix_dispatcher_offset as u64).ok_or(pe::Error::Einval)?;
    let callable = arena.checked_add(unix_dispatcher_offset as u64).ok_or(pe::Error::Einval)?;
    let table_end = table_offset.checked_add(syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT * core::mem::size_of::<u64>()).ok_or(pe::Error::Einval)?;
    if table_end > code.len() { return Err(pe::Error::Einval); }
    for slot in code[table_offset..table_end].chunks_exact_mut(core::mem::size_of::<u64>()) {
        slot.copy_from_slice(&callable.to_le_bytes());
    }
    code[data_offset..data_offset + 8].copy_from_slice(&dispatcher.to_le_bytes());
    code[data_offset + 8..data_offset + 16].copy_from_slice(&unix_callable.to_le_bytes());
    code[data_offset + 16..data_offset + 24].copy_from_slice(&syscall::nt::WINE_UNIXLIB_HANDLE.to_le_bytes());
    let data = as_.stash_bytes(code.into_boxed_slice());
    let base = as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(base_address), mapped_bytes, VmaProt::READ | VmaProt::EXEC, VmaProt::READ | VmaProt::EXEC, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data, off: 0 }).map_err(|_| pe::Error::Einval)?;
    for address in &mut addresses { *address = base.as_u64().checked_add(*address).ok_or(pe::Error::Einval)?; }
    let relay_call = base.as_u64().checked_add(relay_offset as u64).ok_or(pe::Error::Einval)?;
    let wine_dispatcher = base.as_u64().checked_add(dispatcher_offset as u64).ok_or(pe::Error::Einval)?;
    let wine_unix_dispatcher = base.as_u64().checked_add(unix_dispatcher_offset as u64).ok_or(pe::Error::Einval)?;
    let wine_unixlib_handle = base.as_u64().checked_add(handle_offset as u64).ok_or(pe::Error::Einval)?;
    let entries = [wine_unix_dispatcher; syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT];
    // Oxide owns the native NTDLL Unix-call implementations in the kernel;
    // this table is the process-local identity Wine stores in
    // __wine_unixlib_handle. The dispatcher validates the bounded entry and
    // executes the typed implementation, so the PE side never receives an
    // arbitrary user pointer as a substitute for the native table.
    if crate::unixlib::register_callable_table(
        as_, crate::unixlib::MappedUnixlib { base: base.as_u64(), end: base.as_u64().checked_add(mapped_bytes as u64).ok_or(pe::Error::Einval)? },
        table_offset as u64, &entries, &[(base.as_u64(), base.as_u64().checked_add(table_end as u64).ok_or(pe::Error::Einval)?)]).is_err() {
        let _ = as_.munmap(base, mapped_bytes);
        return Err(pe::Error::Einval);
    }
    Ok(NtRuntime { base, bytes: mapped_bytes, relay_call, wine_dispatcher, wine_unix_dispatcher, wine_unixlib_handle, addresses })
}

/// Resolve the private run-once callback continuation in the synthetic ntdll page.
pub fn resolve_nt_runtime_run_once_continuation(base: u64) -> Option<u64> {
    let mut offset = 0u64;
    for (index, _) in NTDLL_EXPORTS.iter().enumerate() { offset = offset.checked_add(runtime_stub_bytes(index) as u64)?; }
    base.checked_add(offset)
}
fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
}
struct RejectImports;
impl ImportResolver for RejectImports {
    fn resolve(&self, _dll: &[u8], _import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
        Err(pe::Error::Unsupported)
    }
}
pub fn initial_entry_state(image: &PeLoadedImage, stack_top: u64) -> Result<PeEntryState, pe::Error> {
    // A direct image entry has no caller-generated return address. Reserve
    // its slot anyway so the image observes the Windows x64 callee-entry
    // alignment and its 32-byte home area remains above RSP.
    let rsp = stack_top.checked_sub(process_env::X64_SHADOW_SPACE + process_env::X64_RETURN_SLOT).ok_or(pe::Error::Einval)?;
    let rsp = (rsp & !0xf) | 8;
    Ok(PeEntryState { rip: image.entry, rsp: UserVirtAddr::new(rsp).ok_or(pe::Error::Einval)?, gs_base: UserVirtAddr::new(0).ok_or(pe::Error::Einval)?, personality: ExecutionPersonality::Nt })
}
pub fn initial_entry_state_with_environment(image: &PeLoadedImage, stack_top: u64, env: &process_env::NtProcessEnvironment) -> Result<PeEntryState, pe::Error> {
    let mut state = initial_entry_state(image, stack_top)?;
    state.gs_base = env.teb;
    Ok(state)
}

pub fn load_pe_process(blob: &[u8], as_: &AddressSpace, input: &process_env::EnvironmentInput<'_>, stack_top: u64) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_resolver(blob, as_, input, stack_top, &RejectImports)
}
pub fn load_pe_process_with_resolver<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, resolver: &R) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_resolver_and_modules(blob, as_, input, stack_top, resolver, &[])
}
pub fn load_pe_process_with_catalog(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64,
    runtime: &NtRuntime, catalog: &pe::catalog::ModuleCatalog) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_catalog_and_params(blob, as_, input, stack_top, runtime, catalog, None)
}
pub fn load_pe_process_with_catalog_and_params(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, runtime: &NtRuntime,
    catalog: &pe::catalog::ModuleCatalog,
    params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_catalog_with_stack_bounds(blob, as_, input, 0, stack_top, runtime, runtime, catalog, params)
}
/// Name what stopped the module graph before the status that reaches the
/// caller erases it. A catalog that cannot supply a module is a fact about
/// the set the launcher handed over, and it is invisible in the single
/// image-format status the execution boundary is allowed to return.
fn report_discover_failure(failure: pe::DiscoverFailure) -> pe::Error {
    match &failure {
        pe::DiscoverFailure::Image(_) => klog::write_raw(b"[WINDOWS-PE-CATALOG] outcome=unparsable-image\n"),
        pe::DiscoverFailure::MissingModule { needed, requested_by, forwarded } => {
            klog::write_raw(b"[WINDOWS-PE-CATALOG] outcome=missing-module needed=");
            klog::write_raw(needed);
            klog::write_raw(b" requested-by=");
            klog::write_raw(requested_by);
            klog::write_raw(if *forwarded { b" reached=forwarded-export\n" } else { b" reached=import-descriptor\n" });
        }
    }
    failure.error()
}

pub fn load_pe_process_with_catalog_and_params_with_stack_bounds(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_base: u64, stack_top: u64, runtime: &NtRuntime,
    catalog: &pe::catalog::ModuleCatalog,
    params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_catalog_with_stack_bounds(blob, as_, input, stack_base, stack_top, runtime, runtime, catalog, params)
}
fn load_pe_process_with_catalog_with_stack_bounds<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_base: u64, stack_top: u64, runtime: &NtRuntime, fallback: &R,
    catalog: &pe::catalog::ModuleCatalog, params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    let source = catalog;
    // The shipped runtime numbers its own services. Install that numbering
    // from the catalog, before discovery and before anything is mapped: it is
    // a fact about the module, and without it a stock service stub's bare
    // ordinal is indistinguishable from the Linux syscall of the same number.
    if let Some(blob) = source.load(b"ntdll.dll") {
        if let Ok(image) = pe::parse(blob) { let _ = crate::nt_ordinals::install_from_image(&image); }
    }
    let owned = pe::discover_owned_modules_detailed(input.image_path.as_bytes(), blob, &source,
        |name| ascii_eq_ignore_case(name, b"ntdll.dll") && source.load(name).is_none())
        .map_err(report_discover_failure)?;
    let loaded = load_owned_pe_module_graph(&owned, as_, fallback, runtime.relay_call)?;
    let mut environment_input = input.clone();
    environment_input.image_base = loaded[0].image.base;
    environment_input.image_size = loaded[0].image.size;
    let mut modules = alloc::vec::Vec::new();
    for (index, module) in loaded.iter().enumerate() {
        let full_name = if index == 0 { input.image_path } else {
            match core::str::from_utf8(module.name) {
                Ok(name) => name,
                Err(_) => { unmap_loaded_modules(as_, &loaded); return Err(pe::Error::Einval); }
            }
        };
        let base_name = full_name.rsplit(['\\', '/']).next().unwrap_or(full_name);
        modules.push(process_env::NtModuleInput {
            base: module.image.base, entry: module.image.entry.as_u64(),
            size: module.image.size, full_name, base_name,
        });
    }
    if !loaded.iter().any(|module| ascii_eq_ignore_case(module.name, b"ntdll.dll")) {
        modules.push(process_env::NtModuleInput {
            base: runtime.base.as_u64(), entry: 0, size: runtime.bytes as u32,
            full_name: "C:\\Windows\\System32\\ntdll.dll", base_name: "ntdll.dll",
        });
    }
    let environment = match params.map_or_else(
        || process_env::build_with_modules_and_stack(&environment_input, &modules, stack_base, stack_top, as_),
        |params| process_env::build_with_modules_and_params_and_stack(&environment_input, &modules, params, stack_base, stack_top, as_)) {
        Ok(environment) => environment,
        Err(error) => {
            unmap_loaded_modules(as_, &loaded);
            return Err(error);
        }
    };
    let mut entry = match initial_entry_state_with_environment(&loaded[0].image, stack_top, &environment) {
        Ok(entry) => entry,
        Err(error) => {
            let _ = as_.munmap(environment.base, environment.bytes);
            unmap_loaded_modules(as_, &loaded);
            return Err(error);
        }
    };
    let initializers = match pe_init::collect_initializers(&loaded, &owned) {
        Ok(initializers) => initializers,
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); unmap_loaded_modules(as_, &loaded); return Err(error); }
    };
    let exit_entry = match resolve_nt_runtime_export(runtime.base.as_u64(), b"RtlExitUserProcess")
        .and_then(UserVirtAddr::new) { Some(entry) => entry, None => {
            let _ = as_.munmap(environment.base, environment.bytes);
            unmap_loaded_modules(as_, &loaded);
            return Err(pe::Error::Unsupported);
        }};
    let initializer_trampoline = match pe_init::map_with_exit(as_, entry.rip, &initializers, exit_entry) {
        Ok(trampoline) => Some(trampoline),
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); unmap_loaded_modules(as_, &loaded); return Err(error); }
    };
    if let Some(trampoline) = initializer_trampoline { entry.rip = trampoline.entry; }
    let startup = match crate::pe_startup::PeStartupTransaction::begin(as_, &loaded[0].image, &environment, stack_base, stack_top, &entry, initializer_trampoline.as_ref()) {
        Ok(transaction) => transaction,
        Err(_) => {
            let _ = as_.munmap(environment.base, environment.bytes);
            unmap_loaded_modules(as_, &loaded);
            return Err(pe::Error::Einval);
        }
    };
    let mut runtime_modules = loaded.iter().zip(&owned).map(|(module, owned)| -> Result<_, pe::Error> { Ok(pe_modules::PeRuntimeModule { base: module.image.base, size: module.image.size, exception_rva: module.image.exception_directory.0, exception_size: module.image.exception_directory.1, exception_functions: pe::parse(&owned.blob)?.exception_functions()? }) }).collect::<Result<alloc::vec::Vec<_>, _>>()?;
    if !loaded.iter().any(|module| ascii_eq_ignore_case(module.name, b"ntdll.dll")) {
        runtime_modules.push(pe_modules::PeRuntimeModule { base: runtime.base.as_u64(), size: runtime.bytes as u32, exception_rva: 0, exception_size: 0, exception_functions: alloc::vec::Vec::new() });
    }
    pe_modules::register(as_, &runtime_modules);
    for (module, owned_module) in loaded.iter().zip(&owned) {
        if let Some(rvas) = pe::parse(&owned_module.blob)?.export_rvas()? {
            pe_modules::register_exports(as_, module.image.base, rvas);
        }
    }
    Ok(PeProcess { image: loaded[0].image, environment, entry, startup, initializers, initializer_trampoline })
}

#[cfg(test)]
fn load_pe_process_with_catalog_with_fallback<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, runtime: &NtRuntime, fallback: &R,
    catalog: &pe::catalog::ModuleCatalog, params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_catalog_with_stack_bounds(blob, as_, input, 0, stack_top, runtime, fallback, catalog, params)
}
fn unmap_loaded_modules(as_: &AddressSpace, loaded: &[PeLoadedModule<'_>]) {
    for module in loaded {
        if let Some(base) = UserVirtAddr::new(module.image.base) {
            let _ = as_.munmap(base, module.image.size as usize);
        }
    }
}
pub fn load_pe_process_with_resolver_and_modules<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, resolver: &R, additional_modules: &[process_env::NtModuleInput<'_>]) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_resolver_and_modules_and_params(blob, as_, input, stack_top, resolver, additional_modules, None)
}
pub fn load_pe_process_with_resolver_and_modules_and_params<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_top: u64, resolver: &R,
    additional_modules: &[process_env::NtModuleInput<'_>], params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    load_pe_process_with_resolver_and_modules_and_params_with_stack_bounds(blob, as_, input, 0, stack_top, resolver, additional_modules, params)
}
pub fn load_pe_process_with_resolver_and_modules_and_params_with_stack_bounds<R: ImportResolver>(blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_base: u64, stack_top: u64, resolver: &R,
    additional_modules: &[process_env::NtModuleInput<'_>], params: Option<&process_env::NtProcessParameters<'_>>) -> Result<PeProcess, pe::Error> {
    let image = load_pe_image_with_resolver(blob, as_, resolver)?;
    // PEB image metadata belongs to the mapped image, not to caller-supplied
    // bookkeeping. Keep the other process strings/IDs from the caller while
    // deriving these two fields from the validated PE headers and placement.
    let mut environment_input = input.clone();
    environment_input.image_base = image.base;
    environment_input.image_size = image.size;
    let root_name = input.image_path.rsplit(['\\', '/']).next().unwrap_or(input.image_path);
    let mut modules = alloc::vec![process_env::NtModuleInput { base: image.base, entry: image.entry.as_u64(), size: image.size, full_name: input.image_path, base_name: root_name }];
    modules.extend_from_slice(additional_modules);
    let environment = match params.map_or_else(
        || process_env::build_with_modules_and_stack(&environment_input, &modules, stack_base, stack_top, as_),
        |params| process_env::build_with_modules_and_params_and_stack(&environment_input, &modules, params, stack_base, stack_top, as_)) {
        Ok(environment) => environment,
        Err(error) => { let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); }
    };
    let entry = match initial_entry_state_with_environment(&image, stack_top, &environment) {
        Ok(entry) => entry,
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); }
    };
    let initializers = match pe_init::collect_root_initializers(blob, &image) { Ok(initializers) => initializers, Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); } };
    let initializer_trampoline = match pe_init::map(as_, entry.rip, &initializers) {
        Ok(trampoline) => trampoline,
        Err(error) => { let _ = as_.munmap(environment.base, environment.bytes); let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize); return Err(error); }
    };
    let entry = if let Some(trampoline) = initializer_trampoline { PeEntryState { rip: trampoline.entry, ..entry } } else { entry };
    let startup = match crate::pe_startup::PeStartupTransaction::begin(as_, &image, &environment, stack_base, stack_top, &entry, initializer_trampoline.as_ref()) {
        Ok(transaction) => transaction,
        Err(_) => {
            let _ = as_.munmap(environment.base, environment.bytes);
            let _ = as_.munmap(UserVirtAddr::new(image.base).ok_or(pe::Error::Einval)?, image.size as usize);
            return Err(pe::Error::Einval);
        }
    };
    pe_modules::register(as_, &[pe_modules::PeRuntimeModule { base: image.base, size: image.size, exception_rva: image.exception_directory.0, exception_size: image.exception_directory.1, exception_functions: pe::parse(blob)?.exception_functions()? }]);
    Ok(PeProcess { image, environment, entry, startup, initializers, initializer_trampoline })
}
/// Map one validated PE32+ image into the common address space. # C: O(SizeOfImage + N_sections)
pub fn load_pe_image(blob: &[u8], as_: &AddressSpace) -> Result<PeLoadedImage, pe::Error> {
    load_pe_image_with_resolver(blob, as_, &RejectImports)
}
pub fn load_pe_image_with_resolver<R: ImportResolver>(blob: &[u8], as_: &AddressSpace, resolver: &R) -> Result<PeLoadedImage, pe::Error> {
    load_pe_image_with_resolver_at(blob, as_, resolver, None, 0)
}
/// Map one validated image using the shared import resolver and optional exact placement. # C: O(SizeOfImage + N_sections)
pub fn load_pe_image_with_resolver_at<R: ImportResolver>(blob: &[u8], as_: &AddressSpace, resolver: &R, exact_base: Option<UserVirtAddr>, relay_call: u64) -> Result<PeLoadedImage, pe::Error> {
    load_pe_image_with_resolver_at_mode(blob, as_, resolver, exact_base, relay_call, true)
}
fn load_pe_image_with_resolver_at_mode<R: ImportResolver>(blob: &[u8], as_: &AddressSpace, resolver: &R, exact_base: Option<UserVirtAddr>, relay_call: u64, validate_imports: bool) -> Result<PeLoadedImage, pe::Error> {
    let parsed = pe::parse(blob)?;
    // Validate every image-owned TLS address before binding or reserving
    // anything; malformed TLS must leave no VMA behind.
    validate_tls_directory(&parsed)?;
    let _tls_callbacks = parsed.tls_callback_rvas()?;
    let mut image = parsed.materialize()?;
    let len = parsed.size_of_image as usize;
    // Reserve the whole image first. This obtains the preferred base when it
    // is clear, or an ASLR fallback, without exposing a partially mapped PE.
    // The new exec address space is private and not concurrently modified.
    let reservation = match exact_base {
        Some(base) => as_.mmap_with_may_at(MmapPlacement::Fixed(base), len, VmaProt::READ | VmaProt::WRITE,
            VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC, VmaFlags::PRIVATE, VmaBacking::Anonymous).map_err(|_| pe::Error::Einval)?,
        None => as_.mmap(UserVirtAddr::new(parsed.image_base), len, VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE, VmaBacking::Anonymous, false).map_err(|_| pe::Error::Einval)?,
    };
    let base = reservation.as_u64();
    if let Err(error) = pe::apply_relocations(&mut image, &parsed, base) {
        let _ = as_.munmap(reservation, len);
        return Err(error);
    }
    // Relocations apply to image-owned absolute pointers. Bind external IAT
    // addresses only afterward; otherwise the relocation delta is added to
    // an already-final external function pointer.
    if let Err(error) = bind_imports(&parsed, &mut image, resolver) {
        let _ = as_.munmap(reservation, len);
        return Err(error);
    }
    // Wine owns relay installation. Its loader first records each original
    // EAT target in relay_private_data, then patches the EAT to the generated
    // Windows-ABI thunk. Patching here would make Wine record the thunk as
    // orig_func and the native RelayCall would recurse into that thunk.
    // Imports still resolve relay_export_rva through PeGraphResolver; direct
    // exports remain untouched until Wine has initialized its descriptor.
    if relay_call != 0 {
        if let Some(descriptor_rva) = parsed.relay_descriptor_rva()? {
            let slot = (descriptor_rva as usize).checked_add(8).ok_or(pe::Error::Einval)?;
            let end = slot.checked_add(8).ok_or(pe::Error::Einval)?;
            image.get_mut(slot..end).ok_or(pe::Error::Einval)?.copy_from_slice(&relay_call.to_le_bytes());
            #[cfg(feature = "debug-faultdiag")]
            {
                klog::write_raw(b"[WINDOWS-PE-RELAY] base=");
                klog::write_hex_u64(base);
                klog::write_raw(b" descriptor=");
                klog::write_hex_u64(base.checked_add(descriptor_rva as u64).ok_or(pe::Error::Einval)?);
                klog::write_raw(b" dispatcher=");
                klog::write_hex_u64(relay_call);
                klog::write_raw(b"\n");
            }
        }
    }
    as_.munmap(reservation, len).map_err(|_| pe::Error::Einval)?;
    let data: Arc<[u8]> = as_.stash_bytes(image.into_boxed_slice());
    let image = &*data;
    as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(reservation), len,
        VmaProt::READ, VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC,
        VmaFlags::PRIVATE, VmaBacking::KernelBytes { data: Arc::clone(&data), off: 0 })
        .map_err(|_| pe::Error::Einval)?;
    let mut transaction = PeImageTransaction::new(as_, reservation, len);
    let header_len = align_up(parsed.size_of_headers, parsed.section_alignment);
    as_.mprotect(reservation, header_len as usize, VmaProt::READ).map_err(|_| pe::Error::Einval)?;
    for section in &parsed.sections {
        let span = align_up(section.virtual_size.max(section.raw_size), parsed.section_alignment);
        if span == 0 { continue; }
        let prot = section_prot(section.characteristics)?;
        let start = base.checked_add(section.virtual_address as u64).ok_or(pe::Error::Einval)?;
        as_.mprotect(UserVirtAddr::new(start).ok_or(pe::Error::Einval)?, span as usize, prot).map_err(|_| pe::Error::Einval)?;
    }
    // IAT entries are indirect code-transfer targets. Validate them only
    // after final section protections are installed, so the resolver cannot
    // admit a mapped writable target that faults on the first import.
    if validate_imports { validate_bound_imports(&parsed, image, as_)?; }
    let entry = UserVirtAddr::new(base.checked_add(parsed.entry_rva as u64).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)?;
    // The transfer address is executable code, not merely an in-range RVA.
    // Keep this check in the loader transaction so a malformed image cannot
    // publish a task that will fault on its first user instruction.
    if !executable_entry(as_, entry) { return Err(pe::Error::Einval); }
    let exception = parsed.directories[pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    let tls = parsed.directories[pe::IMAGE_DIRECTORY_ENTRY_TLS];
    transaction.commit();
    Ok(PeLoadedImage { base, preferred_base: parsed.image_base, entry, size: parsed.size_of_image, exception_directory: (exception.rva, exception.size), tls_directory: (tls.rva, tls.size) })
}

/// Validate the image-owned addresses consumed by the initial TLS setup.
/// Callback-array contents are checked separately by `tls_callback_rvas`.
/// `AddressOfIndex` is a loader write target, so admitting it outside the
/// image would make a later process-attach mutation target unrelated memory.
fn validate_tls_directory(image: &pe::Image<'_>) -> Result<(), pe::Error> {
    let Some(tls) = image.tls()? else { return Ok(()); };
    let image_base = image.image_base;
    let image_size = image.size_of_image as u64;
    let to_rva = |address: u64| address.checked_sub(image_base).ok_or(pe::Error::Einval);
    let in_image = |rva: u64, bytes: u64| {
        rva.checked_add(bytes).map_or(false, |end| end <= image_size)
    };
    if (tls.start_raw == 0) != (tls.end_raw == 0) { return Err(pe::Error::Einval); }
    let (start, end) = if tls.start_raw == 0 { (0, 0) } else {
        (to_rva(tls.start_raw)?, to_rva(tls.end_raw)?)
    };
    if start > end || !in_image(start, end - start) { return Err(pe::Error::Einval); }
    if tls.index != 0 {
        let index = to_rva(tls.index)?;
        if !in_image(index, core::mem::size_of::<u32>() as u64) { return Err(pe::Error::Einval); }
    }
    let _ = (tls.zero_fill as u64).checked_add(end - start).ok_or(pe::Error::Einval)?;
    Ok(())
}
pub fn load_pe_module_set_with_resolver<'a, R: ImportResolver>(modules: &[pe::Module<'a>], as_: &AddressSpace, resolver: &R) -> Result<alloc::vec::Vec<PeLoadedModule<'a>>, pe::Error> {
    let mut loaded = alloc::vec::Vec::new();
    for module in modules {
        match load_pe_image_with_resolver(module.image.raw, as_, resolver) {
            Ok(image) => loaded.push(PeLoadedModule { name: module.name, image }),
            Err(error) => {
                for module in loaded { if let Some(base) = UserVirtAddr::new(module.image.base) { let _ = as_.munmap(base, module.image.size as usize); } }
                return Err(error);
            }
        }
    }
    Ok(loaded)
}
pub fn load_pe_module_graph<'a, R: ImportResolver>(modules: &[pe::Module<'a>], as_: &AddressSpace, fallback: &R, relay_call: u64) -> Result<alloc::vec::Vec<PeLoadedModule<'a>>, pe::Error> {
    let mut bases: alloc::vec::Vec<PeModuleBase<'a>> = alloc::vec::Vec::new();
    for module in modules {
        let size = module.image.size_of_image as usize;
        let reservation = match as_.mmap(UserVirtAddr::new(module.image.image_base), size, VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE, VmaBacking::Anonymous, false) {
            Ok(base) => base,
            Err(_) => {
                for entry in &bases { let _ = as_.munmap(UserVirtAddr::new(entry.base).ok_or(pe::Error::Einval)?, entry.size as usize); }
                return Err(pe::Error::Einval);
            }
        };
        bases.push(PeModuleBase { name: module.name, base: reservation.as_u64(), size: module.image.size_of_image });
    }
    #[cfg(feature = "debug-faultdiag")]
    for module in &bases {
        klog::write_raw(b"[WINDOWS-PE-MODULE] name=");
        klog::write_raw(module.name);
        klog::write_raw(b" base=");
        klog::write_hex_u64(module.base);
        klog::write_raw(b" size=");
        klog::write_hex_u64(module.size as u64);
        klog::write_raw(b"\n");
    }
    let mut exports = alloc::vec::Vec::new();
    for (module, base) in modules.iter().zip(&bases) { exports.push(PeExportRef { name: module.name, image: &module.image, base: base.base }); }
    let resolver = PeGraphResolver { modules: &exports, fallback };
    let mut loaded = alloc::vec::Vec::new();
    for (module, base) in modules.iter().zip(&bases) {
        match load_pe_image_with_resolver_at_mode(module.image.raw, as_, &resolver, UserVirtAddr::new(base.base), relay_call, false) {
            Ok(image) => loaded.push(PeLoadedModule { name: module.name, image }),
            Err(error) => {
                for entry in &bases { if let Some(address) = UserVirtAddr::new(entry.base) { let _ = as_.munmap(address, entry.size as usize); } }
                return Err(error);
            }
        }
    }
    Ok(loaded)
}
pub fn load_owned_pe_module_graph<'a, R: ImportResolver>(modules: &'a [pe::OwnedModule], as_: &AddressSpace, fallback: &R, relay_call: u64) -> Result<alloc::vec::Vec<PeLoadedModule<'a>>, pe::Error> {
    let mut views = alloc::vec::Vec::new();
    for module in modules {
        views.push(pe::Module { name: &module.name, image: pe::parse(&module.blob)? });
    }
    load_pe_module_graph(&views, as_, fallback, relay_call)
}
fn validate_bound_imports(parsed: &pe::Image<'_>, image: &[u8], as_: &AddressSpace) -> Result<(), pe::Error> {
    for import in parsed.imports()? {
        let thunks = parsed.import_thunks(&import)?;
        for (index, _) in thunks.iter().enumerate() {
            let offset = (import.first_thunk as usize).checked_add(index.checked_mul(8).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)?;
            let end = offset.checked_add(8).ok_or(pe::Error::Einval)?;
            let address = u64::from_le_bytes(image.get(offset..end).ok_or(pe::Error::Einval)?.try_into().map_err(|_| pe::Error::Einval)?);
            let target = UserVirtAddr::new(address).ok_or(pe::Error::Einval)?;
            let vma = as_.find_vma(target).ok_or(pe::Error::Einval)?;
            if !vma.prot.contains(VmaProt::EXEC) { return Err(pe::Error::Einval); }
        }
    }
    Ok(())
}

fn bind_imports<R: ImportResolver>(parsed: &pe::Image<'_>, image: &mut [u8], resolver: &R) -> Result<(), pe::Error> {
    for import in parsed.imports()? {
        let thunks = parsed.import_thunks(&import)?;
        for (index, thunk) in thunks.iter().enumerate() {
            let offset = (import.first_thunk as usize).checked_add(index.checked_mul(8).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)?;
            let end = offset.checked_add(8).ok_or(pe::Error::Einval)?;
            if end > image.len() || !parsed.sections.iter().any(|section| {
                let section_end = section.virtual_address.saturating_add(section.virtual_size.max(section.raw_size));
                (offset as u32) >= section.virtual_address && (end as u32) <= section_end
                    && section.characteristics.contains(pe::SectionFlags::MEM_WRITE)
            }) { return Err(pe::Error::Einval); }
            let address = match resolver.resolve(import.name, thunk) {
                Ok(address) => address,
                Err(error) => return Err(error),
            };
            #[cfg(feature = "debug-faultdiag")]
            if import.name.eq_ignore_ascii_case(b"ntdll.dll")
                && matches!(thunk, pe::ImportThunk::Name { name, .. } if *name == b"RtlGetVersion" || *name == b"RtlRunOnceExecuteOnce") {
                klog::write_raw(b"[WINDOWS-PE-BIND-NT] name=");
                if let pe::ImportThunk::Name { name, .. } = thunk { klog::write_raw(name); }
                klog::write_raw(b" address=");
                klog::write_hex_u64(address);
                klog::write_raw(b"\n");
            }
            #[cfg(feature = "debug-faultdiag")]
            if (0x1800_04c00..0x1800_05000).contains(&address) {
                klog::write_raw(b"[WINDOWS-PE-BIND] dll=");
                klog::write_raw(import.name);
                klog::write_raw(b" symbol=");
                match thunk {
                    pe::ImportThunk::Name { name, .. } => klog::write_raw(name),
                    pe::ImportThunk::Ordinal(ordinal) => klog::write_dec_u64(*ordinal as u64),
                }
                klog::write_raw(b" address=");
                klog::write_hex_u64(address);
                klog::write_raw(b"\n");
            }
            image[offset..end].copy_from_slice(&address.to_le_bytes());
        }
    }
    Ok(()) } fn section_prot(flags: SectionFlags) -> Result<VmaProt, pe::Error> {
    let mut prot = VmaProt::empty(); if flags.contains(SectionFlags::MEM_READ) { prot |= VmaProt::READ; } if flags.contains(SectionFlags::MEM_WRITE) { prot |= VmaProt::WRITE; } if flags.contains(SectionFlags::MEM_EXECUTE) { prot |= VmaProt::EXEC; } Ok(prot) } fn align_up(v: u32, a: u32) -> u32 { v.saturating_add(a - 1) & !(a - 1) } #[cfg(test)] #[path = "tests/pe_loader.rs"] mod tests;
