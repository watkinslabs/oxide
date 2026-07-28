// `kernel.randomize_va_space` — the single cell that decides whether an exec
// randomises, and how far. `procfs` binds its sysctl leaf to these accessors;
// there is no second copy of the value anywhere.

use core::sync::atomic::{AtomicI32, Ordering};

/// Linux `randomize_va_space` default with `CONFIG_COMPAT_BRK` disabled —
/// the modern-distro configuration (`mm/memory.c:121-126`).
pub const DEFAULT: i32 = 2;

/// Linux `int randomize_va_space __read_mostly` (`mm/memory.c:121`).
static RANDOMIZE_VA_SPACE: AtomicI32 = AtomicI32::new(DEFAULT);

/// Interpretation of `randomize_va_space`, per
/// `Documentation/admin-guide/sysctl/kernel.rst:1208-1227`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode {
    /// `0`: nothing is randomised. What `norandmaps` and `setarch -R` want.
    Off,
    /// `1`: mmap base, stack, vDSO and the PIE load bias randomise; the heap
    /// (`brk`) does not.
    Conservative,
    /// `2`: everything in `Conservative`, plus `brk`.
    Full,
}

impl Mode {
    /// Linux reads the raw int in two places and nowhere else: `!= 0` arms
    /// `PF_RANDOMIZE` (`fs/binfmt_elf.c:1021`) and `> 1` arms
    /// `arch_randomize_brk` (`fs/binfmt_elf.c:1332`). `proc_dointvec` with no
    /// `extra1`/`extra2` accepts any int, so values outside 0..=2 are reachable
    /// and must fold the same way Linux folds them.
    /// # C: O(1)
    pub const fn from_raw(raw: i32) -> Self {
        if raw == 0 { Mode::Off } else if raw > 1 { Mode::Full } else { Mode::Conservative }
    }

    /// True when this mode randomises anything at all (Linux `!= 0`).
    /// # C: O(1)
    pub const fn randomizes(self) -> bool { !matches!(self, Mode::Off) }

    /// True when `brk` randomises too (Linux `> 1`).
    /// # C: O(1)
    pub const fn randomizes_brk(self) -> bool { matches!(self, Mode::Full) }
}

/// Live `kernel.randomize_va_space` value. # C: O(1)
pub fn randomize_va_space() -> i32 { RANDOMIZE_VA_SPACE.load(Ordering::Relaxed) }

/// `proc_dointvec` write path for `kernel.randomize_va_space`. # C: O(1)
pub fn set_randomize_va_space(v: i32) { RANDOMIZE_VA_SPACE.store(v, Ordering::Relaxed) }

/// Current mode. # C: O(1)
pub fn mode() -> Mode { Mode::from_raw(randomize_va_space()) }

/// Linux `fs/binfmt_elf.c:1021`:
/// `if (!(current->personality & ADDR_NO_RANDOMIZE) && snapshot_randomize_va_space)`
/// `current->flags |= PF_RANDOMIZE;`
///
/// `no_randomize` is the caller's `personality & ADDR_NO_RANDOMIZE` test — the
/// bit itself stays owned by `sched::personality`, so `personality(2)` and this
/// decision cannot drift apart.
/// # C: O(1)
pub const fn pf_randomize(mode: Mode, no_randomize: bool) -> bool {
    !no_randomize && mode.randomizes()
}

/// Linux's brk gate: `(current->flags & PF_RANDOMIZE) && randomize_va_space > 1`
/// (`fs/binfmt_elf.c:1332`). Note it is NOT "mode is Full" alone —
/// `ADDR_NO_RANDOMIZE` suppresses the heap move as well.
/// # C: O(1)
pub const fn randomize_brk(mode: Mode, no_randomize: bool) -> bool {
    pf_randomize(mode, no_randomize) && mode.randomizes_brk()
}
