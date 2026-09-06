//! Delay-load descriptor layout, import selection, and failure-hook policy.
//!
//! Every decision `LdrResolveDelayLoadedAPI` makes lives here so it is testable
//! without the kernel target. `nt_delay_load` owns only user-memory access and
//! the control transfer. Contract: `docs/31gg`.

/// `IMAGE_DELAYLOAD_DESCRIPTOR` is eight little-endian `DWORD`s.
pub const DELAY_DESCRIPTOR_BYTES: usize = 32;
/// `DELAYLOAD_INFO` on x86-64, including trailing alignment.
pub const DELAYLOAD_INFO_BYTES: usize = 0x48;
/// `DELAYLOAD_GPA_FAILURE`: the sole notification reason a delay-load DLL hook
/// receives from this service.
pub const DELAYLOAD_GPA_FAILURE: u64 = 4;
/// One `IMAGE_THUNK_DATA64` entry.
pub const THUNK_BYTES: u64 = 8;
/// `IMAGE_SNAP_BY_ORDINAL64`.
pub const SNAP_BY_ORDINAL: u64 = 0x8000_0000_0000_0000;
/// Largest import-table index this service will index. A thunk further from
/// the table than this is a malformed descriptor, not a large import table.
pub const MAX_THUNK_INDEX: u64 = 0x1_0000;
/// Bytes reserved below the caller's stack pointer for the failure-hook frame:
/// return slot, four home slots, `DELAYLOAD_INFO`, and trailing alignment.
pub const HOOK_FRAME_BYTES: u64 = 0xa0;
/// `DELAYLOAD_INFO` offset inside the reserved hook frame, past the return
/// address and the callee's four home slots.
pub const HOOK_INFO_OFFSET: u64 = 0x28;

const INFO_SIZE_OFFSET: usize = 0x00;
const INFO_DESCRIPTOR_OFFSET: usize = 0x08;
const INFO_THUNK_OFFSET: usize = 0x10;
const INFO_DLL_NAME_OFFSET: usize = 0x18;
const INFO_DESCRIBED_BY_NAME_OFFSET: usize = 0x20;
const INFO_DESCRIPTION_OFFSET: usize = 0x28;
const INFO_MODULE_BASE_OFFSET: usize = 0x30;
const INFO_UNUSED_OFFSET: usize = 0x38;
const INFO_LAST_ERROR_OFFSET: usize = 0x40;

/// Parsed `IMAGE_DELAYLOAD_DESCRIPTOR`. Every field is an RVA against the
/// image base the caller supplied, except the attribute word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelayDescriptor {
    pub attributes: u32,
    pub dll_name_rva: u32,
    pub module_handle_rva: u32,
    pub iat_rva: u32,
    pub int_rva: u32,
    pub bound_iat_rva: u32,
    pub unload_info_rva: u32,
    pub time_date_stamp: u32,
}

/// Which import one delay-load thunk names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportSelector {
    /// `IMAGE_SNAP_BY_ORDINAL64` was set; the low word is the ordinal.
    Ordinal(u16),
    /// The entry is an RVA to an `IMAGE_IMPORT_BY_NAME`; its name starts two
    /// bytes past the hint.
    Name { name_rva: u32 },
}

/// Where control goes when resolution fails, and with which two arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureTarget {
    /// `dllhook(DELAYLOAD_GPA_FAILURE, &info)`.
    DllHook { entry: u64, info: u64 },
    /// `syshook(dll_name, api)`, where `api` is a name pointer or a bare
    /// ordinal value.
    SystemHook { entry: u64, dll_name: u64, api: u64 },
    /// Neither hook was supplied; the resolved address is NULL.
    None,
}

/// Reserved user-stack storage for one failure-hook call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HookFrame { pub rsp: u64, pub info: u64 }

/// # C: O(1)
pub fn parse_descriptor(bytes: &[u8; DELAY_DESCRIPTOR_BYTES]) -> DelayDescriptor {
    let word = |index: usize| u32::from_le_bytes([bytes[index * 4], bytes[index * 4 + 1], bytes[index * 4 + 2], bytes[index * 4 + 3]]);
    DelayDescriptor { attributes: word(0), dll_name_rva: word(1), module_handle_rva: word(2), iat_rva: word(3),
        int_rva: word(4), bound_iat_rva: word(5), unload_info_rva: word(6), time_date_stamp: word(7) }
}

/// Locate one RVA against an image base. A zero RVA names no table.
/// # C: O(1)
pub fn rva_target(base: u64, rva: u32) -> Option<u64> {
    if base == 0 || rva == 0 { return None; }
    base.checked_add(rva as u64)
}

/// Index of one thunk within its import address table. The thunk must lie at
/// or after the table, be entry-aligned, and stay inside the bound.
/// # C: O(1)
pub fn thunk_index(thunk: u64, iat: u64) -> Option<u64> {
    if thunk == 0 || iat == 0 || thunk < iat { return None; }
    let delta = thunk - iat;
    if delta % THUNK_BYTES != 0 { return None; }
    let index = delta / THUNK_BYTES;
    (index <= MAX_THUNK_INDEX).then_some(index)
}

/// Address of one entry in an eight-byte-per-entry import table.
/// # C: O(1)
pub fn slot_address(table: u64, index: u64) -> Option<u64> {
    if table == 0 { return None; }
    table.checked_add(index.checked_mul(THUNK_BYTES)?)
}

/// Classify one import name table entry.
/// # C: O(1)
pub fn import_selector(entry: u64) -> ImportSelector {
    if entry & SNAP_BY_ORDINAL != 0 { ImportSelector::Ordinal(entry as u16) }
    else { ImportSelector::Name { name_rva: entry as u32 } }
}

/// Address of the NUL-terminated name inside an `IMAGE_IMPORT_BY_NAME`, whose
/// first two bytes are the ordinal hint.
/// # C: O(1)
pub fn import_name_address(base: u64, name_rva: u32) -> Option<u64> { rva_target(base, name_rva)?.checked_add(2) }

/// Build the `DELAYLOAD_INFO` a failure hook reads. `description` carries the
/// low word of the raw import-name-table entry for both import forms, matching
/// the observable contract Windows delay-load hooks are written against.
/// # C: O(1)
pub fn serialize_delayload_info(descriptor: u64, thunk: u64, dll_name: u64, described_by_name: bool,
    description: u64, module_base: u64, last_error: u32) -> [u8; DELAYLOAD_INFO_BYTES] {
    let mut bytes = [0u8; DELAYLOAD_INFO_BYTES];
    let scalar = |bytes: &mut [u8; DELAYLOAD_INFO_BYTES], offset: usize, value: u32| { bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); };
    let pointer = |bytes: &mut [u8; DELAYLOAD_INFO_BYTES], offset: usize, value: u64| { bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); };
    scalar(&mut bytes, INFO_SIZE_OFFSET, DELAYLOAD_INFO_BYTES as u32);
    pointer(&mut bytes, INFO_DESCRIPTOR_OFFSET, descriptor);
    pointer(&mut bytes, INFO_THUNK_OFFSET, thunk);
    pointer(&mut bytes, INFO_DLL_NAME_OFFSET, dll_name);
    scalar(&mut bytes, INFO_DESCRIBED_BY_NAME_OFFSET, u32::from(described_by_name));
    pointer(&mut bytes, INFO_DESCRIPTION_OFFSET, description);
    pointer(&mut bytes, INFO_MODULE_BASE_OFFSET, module_base);
    pointer(&mut bytes, INFO_UNUSED_OFFSET, 0);
    scalar(&mut bytes, INFO_LAST_ERROR_OFFSET, last_error);
    bytes
}

/// Select the failure hook and its arguments. A DLL hook, when supplied,
/// takes precedence over the system routine and is the only one that sees the
/// `DELAYLOAD_INFO`.
/// # C: O(1)
pub fn failure_target(dllhook: u64, syshook: u64, info: u64, dll_name: u64, selector: ImportSelector, name_address: u64) -> FailureTarget {
    if dllhook != 0 { return FailureTarget::DllHook { entry: dllhook, info }; }
    if syshook == 0 { return FailureTarget::None; }
    let api = match selector { ImportSelector::Ordinal(ordinal) => ordinal as u64, ImportSelector::Name { .. } => name_address };
    FailureTarget::SystemHook { entry: syshook, dll_name, api }
}

/// Reserve the failure hook's user-stack frame below the interrupted stack
/// pointer. The `DELAYLOAD_INFO` sits above the callee's home area so the
/// hook's own frame, which grows downward from `rsp`, cannot overwrite it.
/// # C: O(1)
pub fn hook_frame(interrupted_rsp: u64) -> Option<HookFrame> {
    let rsp = interrupted_rsp.checked_sub(HOOK_FRAME_BYTES)?;
    if rsp == 0 || rsp & 0xf != 8 { return None; }
    let info = rsp.checked_add(HOOK_INFO_OFFSET)?;
    let end = info.checked_add(DELAYLOAD_INFO_BYTES as u64)?;
    (end <= rsp.checked_add(HOOK_FRAME_BYTES)?).then_some(HookFrame { rsp, info })
}

#[cfg(test)]
#[path = "nt_delay_load_policy/tests.rs"]
mod tests;
