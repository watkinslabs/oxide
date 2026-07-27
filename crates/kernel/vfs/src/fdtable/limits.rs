// `fs.nr_open` — Linux `fs/file.c`'s `sysctl_nr_open` plus the min/max window
// `kernel/sysctl.c` clamps writes to. The fd-table is this value's Linux-shaped
// owner, so `setrlimit(RLIMIT_NOFILE)` (`do_prlimit`) and the
// `/proc/sys/fs/nr_open` proc_handler read ONE live cell instead of each
// carrying a private copy that can disagree.

use core::sync::atomic::{AtomicU32, Ordering};

/// Linux `unsigned int sysctl_nr_open = 1024*1024`.
pub const NR_OPEN_DEFAULT: u32 = 1024 * 1024;

/// Linux `sysctl_nr_open_min = BITS_PER_LONG`. Both kernel targets are LP64.
pub const NR_OPEN_MIN: u32 = 64;

/// Linux `sysctl_nr_open_max = ~0U & ~(BITS_PER_LONG - 1)`.
pub const NR_OPEN_MAX: u32 = u32::MAX & !(NR_OPEN_MIN - 1);

static NR_OPEN: AtomicU32 = AtomicU32::new(NR_OPEN_DEFAULT);

/// Live `sysctl_nr_open` — the hard ceiling `RLIMIT_NOFILE`'s max may reach.
/// # C: O(1)
pub fn nr_open() -> u32 { NR_OPEN.load(Ordering::Relaxed) }

/// `/proc/sys/fs/nr_open` write side. Linux's `proc_dointvec_minmax` rejects
/// out-of-window values; [`clamp_nr_open`] reports whether `v` is inside the
/// window so the handler can reject rather than silently clamp.
/// # C: O(1)
pub fn set_nr_open(v: u32) -> bool {
    if !(NR_OPEN_MIN..=NR_OPEN_MAX).contains(&v) { return false; }
    NR_OPEN.store(v, Ordering::Relaxed);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nr_open_window_matches_linux() {
        assert_eq!(NR_OPEN_DEFAULT, 1_048_576);
        assert_eq!(NR_OPEN_MIN, 64);
        assert_eq!(NR_OPEN_MAX, 0xFFFF_FFC0);
    }

    #[test]
    fn nr_open_write_rejects_values_outside_the_window() {
        assert!(!set_nr_open(NR_OPEN_MIN - 1));
        assert!(!set_nr_open(0));
        assert_eq!(nr_open(), NR_OPEN_DEFAULT, "a rejected write leaves the cell alone");
    }
}
