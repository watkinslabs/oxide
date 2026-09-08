//! The NT runtime support page.
//!
//! One mapped region carries every address the kernel must publish to a
//! Windows runtime module that it does not itself synthesise: the Unix-call
//! and syscall dispatcher trampolines, the Unix-call function table and the
//! identity slot naming it, and the three private continuations a kernel
//! callback returns through.
//!
//! The layout is computed here and nowhere else. Consumers locate an item by
//! the address-space-keyed record this module registers, never by adding a
//! block size to a module base: the runtime module is the real shipped image,
//! whose size has no relationship to the support region.

use alloc::vec::Vec;
use hal::UserVirtAddr;
use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};

/// Byte width of every published pointer slot.
const SLOT_BYTES: usize = core::mem::size_of::<u64>();
/// Data slots the runtime module owns, in publication order.
const DATA_SLOT_COUNT: usize = 3;

/// Offsets of every published item, relative to the start of the region.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SupportOffsets {
    pub run_once_continuation: usize,
    pub wndproc_continuation: usize,
    pub apc_continuation: usize,
    pub syscall_dispatcher_slot: usize,
    pub unix_call_dispatcher_slot: usize,
    pub unixlib_handle_slot: usize,
    pub relay_call: usize,
    pub wine_dispatcher: usize,
    pub wine_unix_dispatcher: usize,
    pub unixlib_handle_datum: usize,
    pub table: usize,
    pub table_end: usize,
    pub bytes: usize,
}

/// Compute the region layout. Pure: no address space, no mapping, no state.
/// # C: O(1)
pub fn support_offsets() -> SupportOffsets {
    let run_once = pe::nt_stub::encode_x64_run_once_continuation(syscall::nt::NtService::RtlRunOnceComplete.entry()).len();
    let wndproc = pe::nt_stub::encode_x64_wndproc_continuation(syscall::nt::NtService::CallbackReturn.entry()).len();
    let apc = pe::nt_stub::encode_x64_apc_continuation().len();
    let dispatcher = pe::nt_stub::encode_x64_wine_dispatcher_stub(syscall::nt::NtService::WineSyscall.entry()).len();
    let unix_dispatcher = pe::nt_stub::encode_x64_unix_call_dispatcher_stub(syscall::nt::NtService::WineUnixCall.entry()).len();
    let run_once_continuation = 0;
    let wndproc_continuation = run_once_continuation + run_once;
    let apc_continuation = wndproc_continuation + wndproc;
    let syscall_dispatcher_slot = apc_continuation + apc;
    let unix_call_dispatcher_slot = syscall_dispatcher_slot + SLOT_BYTES;
    let unixlib_handle_slot = unix_call_dispatcher_slot + SLOT_BYTES;
    let relay_call = syscall_dispatcher_slot + DATA_SLOT_COUNT * SLOT_BYTES;
    let wine_dispatcher = relay_call + pe::nt_stub::X64_RELAY_STUB_BYTES;
    let wine_unix_dispatcher = wine_dispatcher + dispatcher;
    let unixlib_handle_datum = wine_unix_dispatcher + unix_dispatcher;
    let table = unixlib_handle_datum + SLOT_BYTES;
    let table_end = table + syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT * SLOT_BYTES;
    SupportOffsets {
        run_once_continuation, wndproc_continuation, apc_continuation,
        syscall_dispatcher_slot, unix_call_dispatcher_slot, unixlib_handle_slot,
        relay_call, wine_dispatcher, wine_unix_dispatcher, unixlib_handle_datum,
        table, table_end, bytes: table_end,
    }
}

/// Encode the region for a chosen base. Every internal pointer is absolute, so
/// the region cannot be relocated after this returns.
/// # C: O(region bytes)
pub fn build_support_region(base: u64) -> Option<Vec<u8>> {
    let at = support_offsets();
    let mut code = alloc::vec![0u8; at.bytes];
    let mut put = |offset: usize, bytes: &[u8]| -> Option<()> {
        code.get_mut(offset..offset.checked_add(bytes.len())?)?.copy_from_slice(bytes);
        Some(())
    };
    put(at.run_once_continuation, &pe::nt_stub::encode_x64_run_once_continuation(syscall::nt::NtService::RtlRunOnceComplete.entry()))?;
    put(at.wndproc_continuation, &pe::nt_stub::encode_x64_wndproc_continuation(syscall::nt::NtService::CallbackReturn.entry()))?;
    put(at.apc_continuation, &pe::nt_stub::encode_x64_apc_continuation())?;
    put(at.relay_call, &pe::nt_stub::encode_x64_relay_stub(syscall::nt::NtService::RelayCall.entry()))?;
    put(at.wine_dispatcher, &pe::nt_stub::encode_x64_wine_dispatcher_stub(syscall::nt::NtService::WineSyscall.entry()))?;
    put(at.wine_unix_dispatcher, &pe::nt_stub::encode_x64_unix_call_dispatcher_stub(syscall::nt::NtService::WineUnixCall.entry()))?;
    let dispatcher = base.checked_add(at.wine_dispatcher as u64)?;
    let unix_dispatcher = base.checked_add(at.wine_unix_dispatcher as u64)?;
    put(at.syscall_dispatcher_slot, &dispatcher.to_le_bytes())?;
    put(at.unix_call_dispatcher_slot, &unix_dispatcher.to_le_bytes())?;
    put(at.unixlib_handle_slot, &syscall::nt::WINE_UNIXLIB_HANDLE.to_le_bytes())?;
    put(at.unixlib_handle_datum, &syscall::nt::WINE_UNIXLIB_HANDLE.to_le_bytes())?;
    for slot in 0..syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT {
        put(at.table + slot * SLOT_BYTES, &unix_dispatcher.to_le_bytes())?;
    }
    Some(code)
}

/// Absolute addresses the region publishes, for one address space.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtRuntimeSupport {
    pub base: u64,
    pub bytes: u64,
    pub run_once_continuation: u64,
    pub wndproc_continuation: u64,
    pub apc_continuation: u64,
    pub relay_call: u64,
    pub wine_dispatcher: u64,
    pub wine_unix_dispatcher: u64,
    pub syscall_dispatcher_slot: u64,
    pub unix_call_dispatcher_slot: u64,
    pub unixlib_handle_slot: u64,
    /// The standalone handle datum immediately preceding the table.
    pub unixlib_handle_datum: u64,
    pub table_address: u64,
    /// Base of the module whose export table the kernel itself synthesises.
    /// The handover maps a real runtime module and leaves this `None`; the
    /// module then owns its own export and data slots.
    pub synthetic_module: Option<u64>,
}

/// Derive every published address from a mapped region base.
/// # C: O(1)
pub fn describe(base: u64, synthetic_module: Option<u64>) -> Option<NtRuntimeSupport> {
    let at = support_offsets();
    let address = |offset: usize| base.checked_add(offset as u64);
    Some(NtRuntimeSupport {
        base, bytes: at.bytes as u64,
        run_once_continuation: address(at.run_once_continuation)?,
        wndproc_continuation: address(at.wndproc_continuation)?,
        apc_continuation: address(at.apc_continuation)?,
        relay_call: address(at.relay_call)?,
        wine_dispatcher: address(at.wine_dispatcher)?,
        wine_unix_dispatcher: address(at.wine_unix_dispatcher)?,
        syscall_dispatcher_slot: address(at.syscall_dispatcher_slot)?,
        unix_call_dispatcher_slot: address(at.unix_call_dispatcher_slot)?,
        unixlib_handle_slot: address(at.unixlib_handle_slot)?,
        unixlib_handle_datum: address(at.unixlib_handle_datum)?,
        table_address: address(at.table)?,
        synthetic_module,
    })
}

/// Register the Unix-call table and the support record for one address space.
/// The Unix-call service refuses the bootstrap handle until the table exists,
/// so both registrations happen together or neither does.
/// # C: O(table entries)
pub fn publish(as_: &AddressSpace, base: u64, region_end: u64, synthetic_module: Option<u64>)
    -> Result<NtRuntimeSupport, pe::Error>
{
    let at = support_offsets();
    let support = describe(base, synthetic_module).ok_or(pe::Error::Einval)?;
    let entries = [support.wine_unix_dispatcher; syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT];
    let table_end = base.checked_add(at.table_end as u64).ok_or(pe::Error::Einval)?;
    let image = crate::unixlib::MappedUnixlib { base, end: region_end };
    crate::unixlib::register_callable_table(as_, image, at.table as u64, &entries,
        &[(base, table_end)]).map_err(|_| pe::Error::Einval)?;
    crate::elf_modules::register_nt_support(as_, support);
    Ok(support)
}

/// Map the support region into an address space that has no synthetic runtime
/// page of its own, then publish it. Used by the runtime-module handover.
/// # C: O(region bytes)
pub fn map_and_publish(as_: &AddressSpace) -> Result<NtRuntimeSupport, pe::Error> {
    let page = hal::PAGE_SIZE_BYTES as usize;
    let at = support_offsets();
    let mapped_bytes = at.bytes.checked_add(page - 1).ok_or(pe::Error::Einval)? / page * page;
    let arena = as_.get_unmapped_area(mapped_bytes).map_err(|_| pe::Error::Einval)?.as_u64();
    let address = UserVirtAddr::new(arena).ok_or(pe::Error::Einval)?;
    let mut region = build_support_region(arena).ok_or(pe::Error::Einval)?;
    region.resize(mapped_bytes, 0);
    let data = as_.stash_bytes(region.into_boxed_slice());
    let base = as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(address), mapped_bytes,
        VmaProt::READ | VmaProt::EXEC, VmaProt::READ | VmaProt::EXEC, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data, off: 0 }).map_err(|_| pe::Error::Einval)?;
    let end = base.as_u64().checked_add(mapped_bytes as u64).ok_or(pe::Error::Einval)?;
    match publish(as_, base.as_u64(), end, None) {
        Ok(support) => Ok(support),
        Err(error) => { let _ = as_.munmap(base, mapped_bytes); Err(error) }
    }
}

/// The private run-once callback continuation for one address space.
/// # C: O(log N_address_spaces)
pub fn run_once_continuation(root: u64) -> Option<u64> {
    crate::elf_modules::nt_support(root).map(|support| support.run_once_continuation)
}

/// The private window-procedure callback continuation for one address space.
/// # C: O(log N_address_spaces)
pub fn wndproc_continuation(root: u64) -> Option<u64> {
    crate::elf_modules::nt_support(root).map(|support| support.wndproc_continuation)
}

/// The private asynchronous-call return leg for one address space.
/// # C: O(log N_address_spaces)
pub fn apc_continuation(root: u64) -> Option<u64> {
    crate::elf_modules::nt_support(root).map(|support| support.apc_continuation)
}

/// Whether `module` is the kernel-synthesised runtime page in this address
/// space. Only that module's exports may be answered by page arithmetic; a
/// real shipped module owns its own export table.
/// # C: O(log N_address_spaces)
pub fn is_synthetic_module(root: u64, module: u64) -> bool {
    crate::elf_modules::nt_support(root).and_then(|support| support.synthetic_module) == Some(module)
}

#[cfg(test)]
#[path = "nt_support/tests.rs"]
mod tests;
