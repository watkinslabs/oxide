use hal::{PAGE_SIZE_BYTES, USER_VA_END};

/// Lowest user VA this allocator hands out. Page 0 is reserved as the
/// canonical null-pointer trap region per `11§4` (`USER_VA_END` upper
/// bound is in `01§1`).
pub const MIN_USER_VA: u64 = PAGE_SIZE_BYTES;

/// Fallback mmap arena top for ASes whose `mmap_base` was never
/// set (boot anchor, hosted tests). Production ASes get their
/// `mmap_base` programmed at execve time by `aslr::ExecRnd::mmap_base`
/// (Linux `arch_pick_mmap_layout`), so this constant is only the
/// safe-default for non-user contexts. We keep it well below
/// USER_VA_END so any unintentional use still has stack room.
pub const MMAP_TOP: u64 = USER_VA_END - 0x100_0000;

/// Maximum automatic MAP_GROWSDOWN expansion. D32: Linux RLIMIT_STACK
/// default, large enough for musl's wide init frames.
pub(super) const STACK_GROW_MAX: u64 = 8 * 1024 * 1024;
