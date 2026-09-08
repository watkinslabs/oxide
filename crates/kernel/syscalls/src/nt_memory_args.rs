// Argument shape of the virtual-memory and section services: which frame word
// carries which declared argument, which of them are ULONG rather than
// pointer-sized, and which values the services refuse. The decisions stay here,
// ungated, so each one is answerable by a test rather than by a boot.
//
// A stub stores a ULONG argument into a frame word with a 32-bit store, so the
// word's upper half keeps whatever the frame held before the call. Every ULONG
// read out of a frame word is therefore the low half alone, and a refusal of
// the whole word refuses calls no caller made.

use crate::nt_ulong::ulong;

// Stack word indexes of the arguments that do not fit the four register words,
// in each service's declared argument order.
pub const MAP_VIEW_COMMIT_SIZE_ARG: usize = 4;
pub const MAP_VIEW_OFFSET_ARG: usize = 5;
pub const MAP_VIEW_SIZE_ARG: usize = 6;
pub const MAP_VIEW_INHERIT_ARG: usize = 7;
pub const MAP_VIEW_ALLOCATION_TYPE_ARG: usize = 8;
pub const MAP_VIEW_PROTECT_ARG: usize = 9;
pub const MAP_VIEW_EX_ALLOCATION_TYPE_ARG: usize = 5;
pub const MAP_VIEW_EX_PROTECT_ARG: usize = 6;
pub const MAP_VIEW_EX_PARAMETERS_ARG: usize = 7;
pub const MAP_VIEW_EX_COUNT_ARG: usize = 8;
pub const CREATE_SECTION_EX_PARAMETERS_ARG: usize = 7;
pub const CREATE_SECTION_EX_COUNT_ARG: usize = 8;
pub const ALLOCATE_EX_PARAMETERS_ARG: usize = 5;
pub const ALLOCATE_EX_COUNT_ARG: usize = 6;
pub const SET_INFORMATION_MEMORY_LENGTH_ARG: usize = 5;

pub const STATUS_SUCCESS: u64 = 0;
pub const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
pub const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
pub const STATUS_INVALID_PARAMETER_2: u64 = 0xc000_00f0;
pub const STATUS_INVALID_PARAMETER_3: u64 = 0xc000_00f1;
pub const STATUS_INVALID_PARAMETER_4: u64 = 0xc000_00f2;
pub const STATUS_INVALID_PARAMETER_5: u64 = 0xc000_00f3;
pub const STATUS_INVALID_PARAMETER_6: u64 = 0xc000_00f4;
pub const STATUS_INVALID_PARAMETER_9: u64 = 0xc000_00f7;

/// A view whose base is rounded to the page instead of the allocation
/// granularity; only a 32-bit address space offers it.
pub const AT_ROUND_TO_PAGE: u32 = 0x4000_0000;

/// Extended parameters a caller supplied. A count of zero is the whole of the
/// contract this kernel answers for, and it leaves the array unread: the
/// pointer beside a zero count names nothing, so it is not grounds to refuse.
/// # C: O(1)
pub fn extended_parameters_admitted(_parameters: u64, count: u64) -> bool { ulong(count) == 0 }

/// The allocation type a view is mapped with, from its frame word. # C: O(1)
pub fn allocation_type(raw: u64) -> u32 { ulong(raw) as u32 }

/// Whether an allocation type refuses the mapping outright, and with which
/// status. A 64-bit address space has no page-rounded view, and the two
/// services name a different argument for it. # C: O(1)
pub fn map_view_allocation_type_refusal(raw: u64, extended: bool) -> Option<u64> {
    if allocation_type(raw) & AT_ROUND_TO_PAGE == 0 { return None; }
    Some(if extended { STATUS_INVALID_PARAMETER } else { STATUS_INVALID_PARAMETER_9 })
}

/// Information classes the virtual-memory set service answers for.
pub const VM_PREFETCH_INFORMATION: u32 = 0;
pub const VM_PAGE_DIRTY_STATE_INFORMATION: u32 = 3;
/// One `VirtualAddress`/`NumberOfBytes` pair.
pub const MEMORY_RANGE_ENTRY_BYTES: u64 = 16;
/// The word every answered class takes as its information buffer.
pub const VM_INFORMATION_BYTES: u64 = 4;

/// The refusal ladder the virtual-memory set service answers before it reads
/// a single range, in the order the arguments are declared: an unanswered
/// class names the class argument, a missing information buffer and a length
/// that is not one word name theirs, and only then is an empty range array
/// refused. The page-dirty class needs a write-exception owner this kernel
/// does not have, so it is refused as unsupported rather than answered.
/// # C: O(1)
pub fn set_information_refusal(class: u64, count: u64, ptr: u64, length: u64) -> Option<u64> {
    let class = ulong(class) as u32;
    if class == VM_PAGE_DIRTY_STATE_INFORMATION { return Some(STATUS_NOT_SUPPORTED); }
    if class != VM_PREFETCH_INFORMATION { return Some(STATUS_INVALID_PARAMETER_2); }
    if ptr == 0 { return Some(STATUS_INVALID_PARAMETER_5); }
    if ulong(length) as u64 != VM_INFORMATION_BYTES { return Some(STATUS_INVALID_PARAMETER_6); }
    if count == 0 { return Some(STATUS_INVALID_PARAMETER_3); }
    None
}

/// A range entry of no bytes names no memory to prefetch. # C: O(1)
pub const fn range_entry_refusal(bytes: u64) -> Option<u64> {
    if bytes == 0 { Some(STATUS_INVALID_PARAMETER_4) } else { None }
}

/// Where one range entry's byte count sits, from the array base. # C: O(1)
pub fn range_entry_bytes_address(addresses: u64, index: u64) -> Option<u64> {
    addresses.checked_add(index.checked_mul(MEMORY_RANGE_ENTRY_BYTES)?)?.checked_add(8)
}

#[cfg(test)]
#[path = "tests/nt_memory_args.rs"]
mod tests;
