use hal::{PAGE_SIZE_BYTES, USER_VA_END};

/// Lowest user VA this allocator hands out. Page 0 is reserved as the
/// canonical null-pointer trap region per `11§4` (`USER_VA_END` upper
/// bound is in `01§1`).
pub const MIN_USER_VA: u64 = PAGE_SIZE_BYTES;

/// Fallback mmap arena top for ASes whose `mmap_base` was never
/// set (boot anchor, hosted tests). Production ASes get their
/// `mmap_base` programmed at execve time from `arch_pick_mmap_base`
/// (= `stack_top - rlim_stack - MMAP_BASE_GAP`) so this constant is
/// only the safe-default for non-user contexts. We keep it well
/// below USER_VA_END so any unintentional use still has stack room.
pub const MMAP_TOP: u64 = USER_VA_END - 0x100_0000;

/// Linux `STACK_RND_MASK`/`mmap_base` gap below the top of the
/// stack reservation, per `arch/x86/mm/mmap.c arch_pick_mmap_base`.
/// Linux uses 128 MiB plus a randomised slice; v1 uses a fixed
/// 128 MiB (no ASLR yet) so the mmap arena starts that far below
/// the bottom of the rlim_stack reservation. Result: stack can
/// grow up to RLIMIT_STACK without crossing into the mmap arena,
/// and the mmap arena has gigabytes of room beneath it.
pub const MMAP_BASE_GAP: u64 = 128 * 1024 * 1024;

/// Maximum automatic MAP_GROWSDOWN expansion. D32: Linux RLIMIT_STACK
/// default, large enough for musl's wide init frames.
pub(super) const STACK_GROW_MAX: u64 = 8 * 1024 * 1024;
