// The per-exec draw. Linux takes each random word at the point it is needed;
// collecting them into one value drawn at the top of `execve` gives the loader
// a deterministic input it can be tested against, and makes it impossible for
// a caller to re-draw halfway through and produce a layout whose parts
// disagree about where the stack is.

use crate::layout;
use crate::limits::{Budget, CURRENT, STACK_TOP};
use crate::mode::{self, Mode};
use crate::tunable;

/// Linux `arch_pick_mmap_layout`'s two outputs: the arena anchor and the
/// direction `get_unmapped_area` searches from it. They are ONE decision — a
/// legacy base searched downward, or a top-down base searched upward, would
/// each walk straight out of the arena — so they travel together.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Layout {
    /// `mm->mmap_base`: the ceiling when `top_down`, the floor otherwise.
    pub base: u64,
    /// Linux `MMF_TOPDOWN`.
    pub top_down: bool,
}

/// Every random word one exec consumes, plus the decision that produced them.
/// `randomize == false` means every offset below is zero, so an
/// `ADDR_NO_RANDOMIZE` exec and a `randomize_va_space=0` exec produce a
/// byte-identical layout — which is what `setarch -R` and reproducible
/// debugging sessions depend on.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExecRnd {
    /// Linux `PF_RANDOMIZE` for this exec.
    pub randomize: bool,
    /// Linux `PF_RANDOMIZE && randomize_va_space > 1`.
    pub randomize_brk: bool,
    /// `arch_mmap_rnd()` draw for the mmap arena anchor (`arch_pick_mmap_layout`).
    pub mmap_rnd: u64,
    /// The SECOND, independent `arch_mmap_rnd()` draw — the PIE load bias.
    /// Sharing one draw between the arena and the
    /// executable would tie the two together and halve the effective entropy.
    pub load_bias_rnd: u64,
    /// Raw word for `randomize_stack_top`.
    pub stack_raw: u64,
    /// Raw word for `arch_randomize_brk`.
    pub brk_raw: u64,
    /// Raw word for `arch_align_stack`.
    pub align_raw: u64,
    /// Entropy budget in force — the build arch's, except in tests.
    pub budget: Budget,
}

/// A layout with no randomisation at all. Used for the boot anchor address
/// space and for any exec whose personality or sysctl said no.
pub const NONE: ExecRnd = ExecRnd {
    randomize:     false,
    randomize_brk: false,
    mmap_rnd:      0,
    load_bias_rnd: 0,
    stack_raw:     0,
    brk_raw:       0,
    align_raw:     0,
    budget:        CURRENT,
};

impl ExecRnd {
    /// Draw one exec's worth of randomness from the kernel CSPRNG.
    /// `no_randomize` is the caller's `personality & ADDR_NO_RANDOMIZE` test.
    ///
    /// Linux reads `randomize_va_space` ONCE per exec into a snapshot so a
    /// concurrent sysctl write cannot randomise the stack but not the heap;
    /// the single `mode()` read here is that snapshot.
    /// # C: O(1) — five CRNG words
    pub fn draw(no_randomize: bool) -> Self {
        let m = mode::mode();
        Self::draw_with(m, no_randomize, CURRENT, tunable::mmap_rnd_bits())
    }

    /// `draw` with the mode, budget and entropy width supplied — the seam a
    /// hosted test uses to exercise the arch it is not running on.
    /// # C: O(1)
    pub fn draw_with(m: Mode, no_randomize: bool, budget: Budget, rnd_bits: u32) -> Self {
        let randomize = mode::pf_randomize(m, no_randomize);
        if !randomize { return ExecRnd { budget, ..NONE }; }
        ExecRnd {
            randomize:     true,
            randomize_brk: mode::randomize_brk(m, no_randomize),
            mmap_rnd:      layout::arch_mmap_rnd(crng::next_u64(), rnd_bits),
            load_bias_rnd: layout::arch_mmap_rnd(crng::next_u64(), rnd_bits),
            stack_raw:     crng::next_u64(),
            brk_raw:       crng::next_u64(),
            align_raw:     crng::next_u64(),
            budget,
        }
    }

    /// Linux `arch_pick_mmap_layout` top-down result — `mm->mmap_base`, the
    /// ceiling `get_unmapped_area` searches down from.
    /// # C: O(1)
    pub fn mmap_base(&self, rlim_stack: u64) -> u64 {
        layout::mmap_base(self.mmap_rnd, rlim_stack, self.randomize, &self.budget)
    }

    /// Linux `mmap_legacy_base` — the FLOOR the bottom-up layout allocates
    /// upward from. Shares `mmap_rnd` with [`Self::mmap_base`] exactly as
    /// `arch_pick_mmap_base` passes one `random_factor` to both, so a single
    /// exec cannot end up with two independent arena draws.
    /// # C: O(1)
    pub fn mmap_legacy_base(&self) -> u64 {
        layout::mmap_legacy_base(self.mmap_rnd, &self.budget)
    }

    /// Linux `arch_pick_mmap_layout` in full: the anchor address AND the search
    /// direction, decided together and committed to the mm in one step.
    /// `Layout::top_down` is Linux's `MMF_TOPDOWN`.
    /// # C: O(1)
    pub fn mmap_layout(&self, rlim_stack: u64, addr_compat_layout: bool,
                       stack_rlim_unlimited: bool) -> Layout {
        let legacy = layout::mmap_is_legacy(
            addr_compat_layout,
            stack_rlim_unlimited,
            layout::unlimited_stack_flips_layout(),
            crate::tunable::legacy_va_layout(),
        );
        if legacy {
            Layout { base: self.mmap_legacy_base(), top_down: false }
        } else {
            Layout { base: self.mmap_base(rlim_stack), top_down: true }
        }
    }

    /// Linux `randomize_stack_top(STACK_TOP)`.
    /// # C: O(1)
    pub fn stack_top(&self) -> u64 {
        layout::randomize_stack_top(STACK_TOP, self.stack_raw, self.randomize, &self.budget)
    }

    /// Linux ET_DYN + PT_INTERP load bias.
    /// # C: O(1)
    pub fn elf_dyn_load_bias(&self, max_align: u64) -> u64 {
        layout::elf_dyn_load_bias(self.load_bias_rnd, max_align)
    }

    /// Linux's `brk` placement. `moved` is
    /// Linux's `brk_moved`: true when the heap was already relocated to
    /// `ELF_ET_DYN_BASE` because the image itself went into the mmap arena.
    /// When it was NOT moved, Linux steps one page clear of the image end
    /// before randomising, so `start_brk` can never alias the last data page.
    /// Returns `page_align(start)` unchanged when the heap is not randomised.
    /// # C: O(1)
    pub fn brk(&self, start: u64, moved: bool) -> u64 {
        let aligned = layout::page_align_up(start);
        if !self.randomize_brk { return aligned; }
        let base = if moved { aligned } else { aligned + hal::PAGE_SIZE_BYTES };
        layout::arch_randomize_brk(base, self.brk_raw)
    }

    /// Linux `arch_align_stack(p)` at the head of `create_elf_tables`.
    /// # C: O(1)
    pub fn align_stack(&self, sp: u64) -> u64 {
        layout::arch_align_stack(sp, self.align_raw, self.randomize, &self.budget)
    }
}

impl Default for ExecRnd {
    fn default() -> Self { NONE }
}
