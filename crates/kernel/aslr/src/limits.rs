// Entropy budgets and address anchors. Every number here is a Linux constant,
// verified against the reference kernel; nothing is invented.

use hal::{PAGE_SIZE_BYTES, USER_VA_END};

/// `PAGE_SHIFT` — random words are drawn in PAGE units and shifted up, so a
/// randomised base is page-aligned by construction.
pub const PAGE_SHIFT: u32 = PAGE_SIZE_BYTES.trailing_zeros();

/// Linux `DEFAULT_MAP_WINDOW`: the VA span the default mapping window covers.
/// x86_64 spells it `(1UL << 47) - PAGE_SIZE`; arm64 spells the same idea as
/// `1 << VA_BITS_MIN`. This kernel pins
/// ONE user ceiling for both arches — `hal::USER_VA_END`, 47 bits per `01§1` —
/// so both derive the window from it instead of from Linux's per-arch literal.
pub const DEFAULT_MAP_WINDOW: u64 = USER_VA_END - PAGE_SIZE_BYTES;

/// Linux `ELF_ET_DYN_BASE`: the un-randomised load base for a PIE executable
/// that carries a PT_INTERP. x86_64: `DEFAULT_MAP_WINDOW / 3 * 2`. arm64:
/// `2 * DEFAULT_MAP_WINDOW_64 / 3`. Same two-thirds-of-window rule, so one
/// expression serves both. Page-aligned here because `load_bias` is fed
/// through `ELF_PAGESTART` in `load_elf_binary`.
pub const ELF_ET_DYN_BASE: u64 = (DEFAULT_MAP_WINDOW / 3 * 2) & !(PAGE_SIZE_BYTES - 1);

/// Bytes reserved above `STACK_TOP`. Linux puts `STACK_TOP` at `TASK_SIZE`;
/// this kernel keeps the top 64 KiB of the user half clear so a stack pointer
/// one page past the top is still a non-canonical fault rather than a wrap.
pub const STACK_TOP_RESERVE: u64 = 0x1_0000;

/// Linux `STACK_TOP` — the pre-randomisation top of the initial stack.
pub const STACK_TOP: u64 = USER_VA_END - STACK_TOP_RESERVE;

/// Linux `stack_guard_gap`, default `256 << PAGE_SHIFT`: the
/// unmapped band a growable stack keeps below itself. Folded into the mmap
/// gap so the arena can never be adjacent to the stack.
pub const STACK_GUARD_GAP: u64 = 256 * PAGE_SIZE_BYTES;

/// Linux `MIN_GAP`, `SZ_128M` on both arches: the floor on the distance from `STACK_TOP` down to
/// `mmap_base`.
pub const MIN_GAP: u64 = 128 * 1024 * 1024;

/// Linux `MAX_GAP`: `STACK_TOP / 6 * 5`.
pub const MAX_GAP: u64 = STACK_TOP / 6 * 5;

/// Ceiling on the stack VMA this kernel maps up front at execve. Linux maps
/// only the argument pages and grows on demand, so it has no equivalent; here
/// the initial reservation is `min(RLIMIT_STACK, this)` and `MAP_GROWSDOWN`
/// covers the rest. Bounding it is what keeps `mmap_base` clear of
/// `ELF_ET_DYN_BASE` for every reachable `RLIMIT_STACK`.
pub const RLIM_STACK_MAP_CAP: u64 = 1024 * 1024 * 1024;

/// Linux `arch_randomize_brk` range for a native 64-bit task on both arches: `SZ_1G`.
pub const BRK_RND_RANGE: u64 = 1024 * 1024 * 1024;

/// Per-arch randomisation budget. Linux scatters these across Kconfig
/// (`ARCH_MMAP_RND_BITS*`) and arch headers (`STACK_RND_MASK`,
/// `arch_align_stack`). Collecting them in one struct — rather than behind
/// `#[cfg(target_arch)]` at each use site — is what lets a hosted test
/// exercise BOTH arches' address math instead of only the host's.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Budget {
    /// `CONFIG_ARCH_MMAP_RND_BITS` boot value. Neither x86 nor arm64 defines
    /// `ARCH_MMAP_RND_BITS_DEFAULT`, so both boot at their `_MIN`.
    pub mmap_rnd_bits: u32,
    /// `CONFIG_ARCH_MMAP_RND_BITS_MIN` — `vm.mmap_rnd_bits` floor.
    pub mmap_rnd_bits_min: u32,
    /// `CONFIG_ARCH_MMAP_RND_BITS_MAX` — `vm.mmap_rnd_bits` ceiling.
    pub mmap_rnd_bits_max: u32,
    /// `STACK_RND_MASK` — page-count mask in `randomize_stack_top`.
    pub stack_rnd_mask: u64,
    /// `arch_align_stack` jitter ceiling in bytes (exclusive).
    pub align_stack_max: u32,
    /// Divisor in `TASK_UNMAPPED_BASE` — the floor the LEGACY bottom-up mmap
    /// layout allocates upward from. The two arches do NOT agree: x86_64 is
    /// `PAGE_ALIGN(task_size / 3)` and arm64 is `PAGE_ALIGN(window / 4)`, so
    /// the divisor is per-budget rather than one shared constant.
    pub task_unmapped_div: u64,
}

impl Budget {
    /// Linux `TASK_UNMAPPED_BASE` for this arch, over this kernel's single
    /// user window. Bottom-up allocation starts here; it sits low enough that
    /// the legacy arena and the stack cannot meet for any reachable
    /// `RLIMIT_STACK`.
    /// # C: O(1)
    pub const fn task_unmapped_base(&self) -> u64 {
        let raw = DEFAULT_MAP_WINDOW / self.task_unmapped_div;
        (raw + (PAGE_SIZE_BYTES - 1)) & !(PAGE_SIZE_BYTES - 1)
    }
}

/// x86_64. `mmap_rnd_bits` 28..32 (Kconfig),
/// `STACK_RND_MASK = 0x3fffff` (22 bits =
/// 16 GiB of stack-top slop), `arch_align_stack` subtracts
/// `get_random_u32_below(8192)`.
pub const X86_64: Budget = Budget {
    mmap_rnd_bits:     28,
    mmap_rnd_bits_min: 28,
    mmap_rnd_bits_max: 32,
    stack_rnd_mask:    0x3f_ffff,
    align_stack_max:   8192,
    task_unmapped_div: 3,
};

/// aarch64, 4 KiB pages. `mmap_rnd_bits` min 18 (Kconfig);
/// max 30 — the Kconfig's own `ARM64_VA_BITS=47` row,
/// which is this kernel's user VA width, NOT the 33 that a 48-bit-VA arm64
/// would use. `STACK_RND_MASK = 0x3ffff >> (PAGE_SHIFT - 12)`
/// (18 bits = 1 GiB). `arch_align_stack`
/// subtracts `get_random_u32_below(PAGE_SIZE)` — narrower than x86's fixed 8192.
pub const AARCH64: Budget = Budget {
    mmap_rnd_bits:     18,
    mmap_rnd_bits_min: 18,
    mmap_rnd_bits_max: 30,
    stack_rnd_mask:    0x3_ffff >> (PAGE_SHIFT - 12),
    align_stack_max:   PAGE_SIZE_BYTES as u32,
    task_unmapped_div: 4,
};

/// The budget for the arch this kernel is being built for.
#[cfg(target_arch = "aarch64")]
pub const CURRENT: Budget = AARCH64;
#[cfg(not(target_arch = "aarch64"))]
pub const CURRENT: Budget = X86_64;
