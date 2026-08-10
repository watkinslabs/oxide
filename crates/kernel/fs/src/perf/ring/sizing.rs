// `rb_alloc`/`perf_mmap_rb`/`perf_mmap_calc_limits` sizing arithmetic.
//
// Pure over explicit inputs: no VMA, no task, no `user_struct`, so the
// power-of-two rule, the watermark default and the whole mlock ladder are
// hosted-testable.

use syscall::errno::Errno;

/// Bytes per page on both oxide arches.
pub const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
/// `PAGE_SHIFT`.
pub const PAGE_SHIFT: u32 = PAGE_BYTES.trailing_zeros();

/// Default per-user ring allowance in KiB. The LIVE value is one cell in
/// `sched::perf_sw` — the one `/proc/sys/kernel/perf_event_mlock_kb` reads and
/// writes — so this is only its initialiser, re-exported here because the
/// sizing arithmetic is what gives it meaning.
pub use sched::perf_sw::MLOCK_KB_DEFAULT;

/// `perf_mmap`'s ceiling on the mapped page count (`nr_pages > INT_MAX`).
pub const NR_PAGES_MAX: u64 = i32::MAX as u64;

/// `perf_mmap_rb`: the mapping is one control page followed by `2^n` data
/// pages, so the DATA page count is `vma_pages - 1` and must be zero or a
/// power of two — the ring masks instead of dividing.
///
/// `vma_pages == 0` cannot reach here from `perf_mmap` (a zero-length mapping
/// is rejected earlier) but is reported as `-EINVAL` rather than underflowing.
/// # C: O(1)
pub fn data_pages(vma_pages: u64) -> Result<u64, Errno> {
    if vma_pages == 0 || vma_pages > NR_PAGES_MAX { return Err(Errno::Einval); }
    let nr = vma_pages - 1;
    if nr != 0 && !nr.is_power_of_two() { return Err(Errno::Einval); }
    Ok(nr)
}

/// `perf_data_size(rb)` — the ring's data area in bytes. # C: O(1)
pub fn data_size(nr_data_pages: u64) -> u64 { nr_data_pages * PAGE_BYTES }

/// `ring_buffer_init`'s watermark rule: a caller-supplied
/// `attr.wakeup_watermark` is capped at the data size; absent one (or
/// `attr.watermark` clear) the default is half the data area.
/// # C: O(1)
pub fn watermark(data_size: u64, wakeup_watermark: u32, watermark_bit: bool) -> u64 {
    let requested = if watermark_bit { wakeup_watermark as u64 } else { 0 };
    let w = if requested != 0 { core::cmp::min(data_size, requested) } else { 0 };
    if w != 0 { w } else { data_size / 2 }
}

/// `perf_mmap_calc_limits`' per-user page allowance:
/// `sysctl_perf_event_mlock >> (PAGE_SHIFT - 10)`, scaled linearly by the
/// online CPU count. # C: O(1)
pub fn user_lock_limit_pages(mlock_kb: i32, nr_online_cpus: u64) -> u64 {
    let kb = mlock_kb.max(0) as u64;
    (kb >> (PAGE_SHIFT - 10)) * nr_online_cpus.max(1)
}

/// The inputs `perf_mmap_calc_limits` reads out of the task, the user record
/// and the sysctls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlockCtx {
    /// Pages the whole mapping costs (control page included) — `user_extra`.
    pub vma_pages:       u64,
    /// `user->locked_vm` before this mapping.
    pub user_locked:     u64,
    /// `sysctl_perf_event_mlock` (KiB).
    pub mlock_kb:        i32,
    pub nr_online_cpus:  u64,
    /// `mm->pinned_vm` before this mapping.
    pub pinned_vm:       u64,
    /// `RLIMIT_MEMLOCK` in pages.
    pub rlimit_pages:    u64,
    /// `perf_is_paranoid()` — `sysctl_perf_event_paranoid > -1`.
    pub paranoid:        bool,
    /// `capable(CAP_IPC_LOCK)`.
    pub cap_ipc_lock:    bool,
}

/// How a successful mapping is charged: `user_extra` pages against
/// `user->locked_vm` and `extra` pages against `mm->pinned_vm`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MlockCharge { pub user_extra: u64, pub extra: u64 }

/// `perf_mmap_calc_limits` — the split between the per-user allowance and the
/// `RLIMIT_MEMLOCK`-governed remainder. `Err(EPERM)` is the reference's
/// `return -EPERM` when neither the rlimit, the paranoid escape nor
/// `CAP_IPC_LOCK` admits the pinned remainder. # C: O(1)
pub fn calc_limits(c: &MlockCtx) -> Result<MlockCharge, Errno> {
    let user_lock_limit = user_lock_limit_pages(c.mlock_kb, c.nr_online_cpus);
    // `sysctl_perf_event_mlock` may have shrunk since the last mapping, so the
    // already-charged total is clamped before this mapping is added.
    let mut user_locked = core::cmp::min(c.user_locked, user_lock_limit);
    let mut user_extra = c.vma_pages;
    let mut extra = 0u64;
    user_locked = user_locked.saturating_add(user_extra);
    if user_locked > user_lock_limit {
        extra = user_locked - user_lock_limit;
        user_extra = user_extra.saturating_sub(extra);
    }
    let locked = c.pinned_vm.saturating_add(extra);
    if locked <= c.rlimit_pages || !c.paranoid || c.cap_ipc_lock {
        Ok(MlockCharge { user_extra, extra })
    } else {
        Err(Errno::Eperm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_pages_requires_control_page_plus_power_of_two() {
        assert_eq!(data_pages(1), Ok(0));
        assert_eq!(data_pages(2), Ok(1));
        assert_eq!(data_pages(3), Ok(2));
        assert_eq!(data_pages(5), Ok(4));
        assert_eq!(data_pages(129), Ok(128));
        // 3 data pages is not a power of two.
        assert_eq!(data_pages(4), Err(Errno::Einval));
        assert_eq!(data_pages(7), Err(Errno::Einval));
        assert_eq!(data_pages(0), Err(Errno::Einval));
        assert_eq!(data_pages(NR_PAGES_MAX + 1), Err(Errno::Einval));
    }

    #[test]
    fn watermark_defaults_to_half_and_caps_at_data_size() {
        let ds = data_size(4);
        assert_eq!(watermark(ds, 0, false), ds / 2);
        // `attr.watermark` clear means `wakeup_events`, not a byte watermark.
        assert_eq!(watermark(ds, 1024, false), ds / 2);
        assert_eq!(watermark(ds, 1024, true), 1024);
        assert_eq!(watermark(ds, u32::MAX, true), ds);
        // An explicit zero watermark still falls back to half.
        assert_eq!(watermark(ds, 0, true), ds / 2);
    }

    #[test]
    fn user_lock_limit_scales_with_cpus() {
        // 513 KiB >> (12 - 10) == 128 pages on a 4 KiB-page arch.
        let one = user_lock_limit_pages(MLOCK_KB_DEFAULT, 1);
        assert_eq!(one, (MLOCK_KB_DEFAULT as u64) >> (PAGE_SHIFT - 10));
        assert_eq!(user_lock_limit_pages(MLOCK_KB_DEFAULT, 8), one * 8);
        assert_eq!(user_lock_limit_pages(-1, 4), 0);
    }

    fn ctx() -> MlockCtx {
        MlockCtx { vma_pages: 5, user_locked: 0, mlock_kb: MLOCK_KB_DEFAULT,
                   nr_online_cpus: 1, pinned_vm: 0, rlimit_pages: 0,
                   paranoid: true, cap_ipc_lock: false }
    }

    #[test]
    fn small_mapping_is_charged_entirely_to_the_user_allowance() {
        assert_eq!(calc_limits(&ctx()), Ok(MlockCharge { user_extra: 5, extra: 0 }));
    }

    #[test]
    fn overflow_past_the_user_allowance_spills_into_pinned_vm() {
        let limit = user_lock_limit_pages(MLOCK_KB_DEFAULT, 1);
        let mut c = ctx();
        c.vma_pages = limit + 3;
        // No RLIMIT_MEMLOCK headroom and no CAP_IPC_LOCK on a paranoid kernel.
        assert_eq!(calc_limits(&c), Err(Errno::Eperm));
        c.cap_ipc_lock = true;
        assert_eq!(calc_limits(&c), Ok(MlockCharge { user_extra: limit, extra: 3 }));
        c.cap_ipc_lock = false;
        c.rlimit_pages = 3;
        assert_eq!(calc_limits(&c), Ok(MlockCharge { user_extra: limit, extra: 3 }));
        c.rlimit_pages = 2;
        assert_eq!(calc_limits(&c), Err(Errno::Eperm));
        // `perf_event_paranoid == -1` waives the pinned check outright.
        c.paranoid = false;
        assert_eq!(calc_limits(&c), Ok(MlockCharge { user_extra: limit, extra: 3 }));
    }

    #[test]
    fn already_over_limit_user_is_clamped_before_this_mapping_is_added() {
        let limit = user_lock_limit_pages(MLOCK_KB_DEFAULT, 1);
        let mut c = ctx();
        c.user_locked = limit * 4;
        c.cap_ipc_lock = true;
        // The clamp means this mapping spills exactly its own page count.
        assert_eq!(calc_limits(&c), Ok(MlockCharge { user_extra: 0, extra: 5 }));
    }
}
