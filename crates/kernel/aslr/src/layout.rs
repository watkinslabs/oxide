// Pure address math. Every function takes the random word it consumes as an
// argument rather than calling the CRNG, so placement rules are testable
// without an RNG and the same code serves both arches' budgets.

use hal::PAGE_SIZE_BYTES;

use crate::limits::{
    Budget, BRK_RND_RANGE, ELF_ET_DYN_BASE, MAX_GAP, MIN_GAP, PAGE_SHIFT, STACK_GUARD_GAP,
    STACK_TOP,
};

/// Linux `arch_mmap_rnd()` — `arch/x86/mm/mmap.c:70-79` (`arch_rnd`) and the
/// generic `mm/util.c:399-411`, which arm64 uses unchanged:
/// `(get_random_long() & ((1UL << mmap_rnd_bits) - 1)) << PAGE_SHIFT`.
///
/// The shift is what makes the result page-aligned; the mask is what bounds it
/// to the arch's entropy budget.
/// # C: O(1)
pub fn arch_mmap_rnd(raw: u64, rnd_bits: u32) -> u64 {
    if rnd_bits == 0 { return 0; }
    let bits = rnd_bits.min(64 - PAGE_SHIFT);
    (raw & ((1u64 << bits) - 1)) << PAGE_SHIFT
}

/// Linux `mmap_base()` — generic `mm/util.c:433-448` (arm64) and
/// `arch/x86/mm/mmap.c:86-99` (x86_64). Both compute
/// `PAGE_ALIGN(STACK_TOP - gap - rnd)` with
/// `gap = clamp(rlim_stack + stack_guard_gap + (STACK_RND_MASK << PAGE_SHIFT),
///              MIN_GAP, MAX_GAP)`.
///
/// The `STACK_RND_MASK` term is why `mmap_base` must account for the MAXIMUM
/// stack randomisation rather than the draw actually taken: the arena top has
/// to clear the lowest stack the randomiser could ever produce.
/// # C: O(1)
pub fn mmap_base(rnd: u64, rlim_stack: u64, randomize: bool, b: &Budget) -> u64 {
    let mut pad = STACK_GUARD_GAP;
    if randomize { pad = pad.saturating_add(b.stack_rnd_mask << PAGE_SHIFT); }
    let mut gap = rlim_stack.saturating_add(pad);
    if gap < MIN_GAP && MIN_GAP < MAX_GAP { gap = MIN_GAP; } else if gap > MAX_GAP { gap = MAX_GAP; }
    page_align_up(STACK_TOP.saturating_sub(gap).saturating_sub(rnd))
}

/// Linux `randomize_stack_top()` — `mm/util.c:341-355`. Both arches take the
/// non-`STACK_GROWSUP` branch, so the random page count is SUBTRACTED:
/// `PAGE_ALIGN(stack_top) - ((get_random_long() & STACK_RND_MASK) << PAGE_SHIFT)`.
/// # C: O(1)
pub fn randomize_stack_top(stack_top: u64, raw: u64, randomize: bool, b: &Budget) -> u64 {
    let var = if randomize { (raw & b.stack_rnd_mask) << PAGE_SHIFT } else { 0 };
    page_align_up(stack_top).saturating_sub(var)
}

/// Linux `randomize_page()` — `mm/util.c:371-387`. Returns a page-aligned
/// address in `[PAGE_ALIGN(start), PAGE_ALIGN(start) + range)`.
/// # C: O(1)
pub fn randomize_page(start: u64, range: u64, raw: u64) -> u64 {
    let mut range = range;
    let aligned = page_align_up(start);
    if aligned != start { range = range.saturating_sub(aligned - start); }
    let start = aligned;
    if start > u64::MAX - range { range = u64::MAX - start; }
    let pages = range >> PAGE_SHIFT;
    if pages == 0 { return start; }
    start + ((raw % pages) << PAGE_SHIFT)
}

/// Linux `arch_randomize_brk()` — `arch/x86/kernel/process.c:1027-1033` (x86's
/// own strong symbol) and `mm/util.c:389-397` (the `__weak` fallback arm64
/// uses). Both reduce to `randomize_page(mm->brk, SZ_1G)` for a native 64-bit
/// task; the `SZ_32M` arm is compat-only and this kernel has no 32-bit
/// personality.
/// # C: O(1)
pub fn arch_randomize_brk(brk: u64, raw: u64) -> u64 { randomize_page(brk, BRK_RND_RANGE, raw) }

/// Linux `load_elf_binary`'s ET_DYN-with-PT_INTERP branch
/// (`fs/binfmt_elf.c:1139-1146`):
/// ```text
/// load_bias = ELF_ET_DYN_BASE;
/// if (current->flags & PF_RANDOMIZE) load_bias += arch_mmap_rnd();
/// if (alignment) load_bias &= ~(alignment - 1);
/// ```
/// `max_align` is `maximum_alignment()` over the PT_LOADs
/// (`fs/binfmt_elf.c:491-509`): the largest power-of-two `p_align`, which for
/// a hugepage-aligned image can be far coarser than a page and would otherwise
/// leave the segments misaligned against their own `p_vaddr % p_align`.
/// # C: O(1)
pub fn elf_dyn_load_bias(rnd: u64, max_align: u64) -> u64 {
    let bias = ELF_ET_DYN_BASE.saturating_add(rnd);
    if max_align > 1 && max_align.is_power_of_two() { bias & !(max_align - 1) } else { bias }
}

/// Linux `arch_align_stack()` — `arch/x86/kernel/process.c:1020-1025` and
/// `arch/arm64/kernel/process.c:813-818`. Called once per exec on the initial
/// string-area pointer (`fs/binfmt_elf.c:193`, `create_elf_tables`) to shuffle
/// cache-set alignment between processes, then hard-aligned to 16 for the
/// SysV ABI.
///
/// Gated on `randomize_va_space` directly on both arches, NOT on
/// `PF_RANDOMIZE` — so `personality(ADDR_NO_RANDOMIZE)` must be folded into
/// `randomize` by the caller for `setarch -R` to be reproducible.
/// # C: O(1)
pub fn arch_align_stack(sp: u64, raw: u64, randomize: bool, b: &Budget) -> u64 {
    let sp = if randomize && b.align_stack_max > 0 {
        sp.saturating_sub(raw % b.align_stack_max as u64)
    } else {
        sp
    };
    sp & !0xf
}

/// Linux `ELF_PAGEALIGN` / `PAGE_ALIGN`. # C: O(1)
pub fn page_align_up(v: u64) -> u64 { (v + (PAGE_SIZE_BYTES - 1)) & !(PAGE_SIZE_BYTES - 1) }
