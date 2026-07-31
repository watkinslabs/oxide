// `struct rusage` ABI: the `who` selector, the field offsets, and the one
// encoder every producer shares (`getrusage(2)`, and the `rusage` out-param of
// `wait4(2)`/`waitid(2)`). Pure + hosted-tested: the syscall slot files are
// `#[cfg(target_os = "oxide-kernel")]` and cannot host a test, so the layout
// contract lives here and is asserted here.
//
// A wait-family `rusage` is NOT the child's own counters alone: it is the
// child's counters PLUS the counters the child had already accumulated from
// its own reaped children (Linux `RUSAGE_BOTH`). `Rusage::both` folds the two.

use crate::time::ns_to_timeval;

/// `sizeof(struct rusage)` on both supported LP64 arches.
pub const RUSAGE_BYTES: usize = 144;

/// `getrusage(2)` `who` selectors. `RUSAGE_BOTH` is kernel-internal — the
/// wait-family out-param uses it; `sys_getrusage` must reject it.
pub const RUSAGE_SELF:     i32 = 0;
pub const RUSAGE_CHILDREN: i32 = -1;
pub const RUSAGE_BOTH:     i32 = -2;
pub const RUSAGE_THREAD:   i32 = 1;

/// Byte offsets of every `struct rusage` member (LP64). The 7 members with no
/// counter behind them anywhere in this kernel — `ru_ixrss`, `ru_idrss`,
/// `ru_isrss`, `ru_nswap`, `ru_msgsnd`, `ru_msgrcv`, `ru_nsignals` — are
/// unnamed here because they are always zero, exactly as Linux leaves them on
/// a configuration without those accounting sources.
pub const OFF_UTIME_SEC:  usize = 0;
pub const OFF_UTIME_USEC: usize = 8;
pub const OFF_STIME_SEC:  usize = 16;
pub const OFF_STIME_USEC: usize = 24;
pub const OFF_MAXRSS:     usize = 32;
pub const OFF_MINFLT:     usize = 64;
pub const OFF_MAJFLT:     usize = 72;
pub const OFF_INBLOCK:    usize = 88;
pub const OFF_OUBLOCK:    usize = 96;
pub const OFF_NVCSW:      usize = 128;
pub const OFF_NIVCSW:     usize = 136;

/// Bytes per block-I/O "operation" in `ru_inblock`/`ru_oublock`: Linux reports
/// `ioac.read_bytes >> 9`, i.e. 512-byte sectors, not syscall counts.
pub const IO_BLOCK_SHIFT: u32 = 9;

/// `getrusage(2)` accepts only these three; anything else is `EINVAL`
/// (`RUSAGE_BOTH` included — it never reaches userspace). # C: O(1)
pub const fn getrusage_who_valid(who: i32) -> bool {
    who == RUSAGE_SELF || who == RUSAGE_CHILDREN || who == RUSAGE_THREAD
}

/// Byte count → 512-byte block-I/O operation count. # C: O(1)
pub const fn bytes_to_blocks(bytes: u64) -> u64 { bytes >> IO_BLOCK_SHIFT }

/// Every `struct rusage` field this kernel has a source for. Fields with no
/// source stay zero and are not represented.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct Rusage {
    pub utime_ns:  u64,
    pub stime_ns:  u64,
    /// Peak resident set, KiB — the mm's resident-page high-water mark scaled
    /// from pages, which is what makes it a PROCESS property rather than a
    /// per-thread one.
    pub maxrss_kb: u64,
    pub minflt:    u64,
    pub majflt:    u64,
    pub inblock:   u64,
    pub oublock:   u64,
    pub nvcsw:     u64,
    pub nivcsw:    u64,
}

impl Rusage {
    /// Linux `RUSAGE_BOTH`: a task's own counters folded with the counters it
    /// already accumulated from its reaped children. This is what the
    /// wait-family `rusage` out-param reports for the child being reaped.
    /// # C: O(1)
    pub const fn both(own: Rusage, children: Rusage) -> Rusage {
        Rusage {
            utime_ns:  own.utime_ns.saturating_add(children.utime_ns),
            stime_ns:  own.stime_ns.saturating_add(children.stime_ns),
            // Linux takes the MAX of the two high-water marks, not the sum.
            maxrss_kb: if own.maxrss_kb > children.maxrss_kb { own.maxrss_kb } else { children.maxrss_kb },
            minflt:    own.minflt.saturating_add(children.minflt),
            majflt:    own.majflt.saturating_add(children.majflt),
            inblock:   own.inblock.saturating_add(children.inblock),
            oublock:   own.oublock.saturating_add(children.oublock),
            nvcsw:     own.nvcsw.saturating_add(children.nvcsw),
            nivcsw:    own.nivcsw.saturating_add(children.nivcsw),
        }
    }

    /// Serialize to the 144-byte user `struct rusage`. Unrepresented members
    /// are left zero. # C: O(1)
    pub fn encode(&self) -> [u8; RUSAGE_BYTES] {
        let mut b = [0u8; RUSAGE_BYTES];
        let (u_sec, u_usec) = ns_to_timeval(self.utime_ns);
        let (s_sec, s_usec) = ns_to_timeval(self.stime_ns);
        put(&mut b, OFF_UTIME_SEC,  u_sec);
        put(&mut b, OFF_UTIME_USEC, u_usec);
        put(&mut b, OFF_STIME_SEC,  s_sec);
        put(&mut b, OFF_STIME_USEC, s_usec);
        put(&mut b, OFF_MAXRSS,  self.maxrss_kb);
        put(&mut b, OFF_MINFLT,  self.minflt);
        put(&mut b, OFF_MAJFLT,  self.majflt);
        put(&mut b, OFF_INBLOCK, self.inblock);
        put(&mut b, OFF_OUBLOCK, self.oublock);
        put(&mut b, OFF_NVCSW,   self.nvcsw);
        put(&mut b, OFF_NIVCSW,  self.nivcsw);
        b
    }
}

fn put(b: &mut [u8; RUSAGE_BYTES], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// `sizeof(struct tms)` — four `clock_t`, which is `long` on both LP64 arches.
pub const TMS_BYTES: usize = 32;

/// `times(2)` in clock ticks: the calling PROCESS's user/system CPU time, and
/// its reaped children's. `tms_utime`/`tms_stime` cover the whole thread group
/// (Linux `thread_group_cputime_adjusted`), not the calling thread.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct Tms {
    pub utime_ticks:  u64,
    pub stime_ticks:  u64,
    pub cutime_ticks: u64,
    pub cstime_ticks: u64,
}

impl Tms {
    /// Serialize to the 32-byte user `struct tms`. # C: O(1)
    pub fn encode(&self) -> [u8; TMS_BYTES] {
        let mut b = [0u8; TMS_BYTES];
        for (i, v) in [self.utime_ticks, self.stime_ticks, self.cutime_ticks, self.cstime_ticks]
            .iter().enumerate()
        {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }
}

/// `times(2)` accepts a NULL `tms` and still returns the tick count — it does
/// NOT report EFAULT. Only a non-NULL pointer is validated. # C: O(1)
pub const fn times_wants_tms(ptr: u64) -> bool { ptr != 0 }

/// `times(2)`'s return value is a tick count, not a status: the kernel forces
/// a successful return so a legitimately large tick count is never mistaken
/// for an errno. Only the exact `(clock_t)-1` bit pattern is the error report,
/// and a monotonic tick count reaches it only after the counter wraps.
/// # C: O(1)
pub const fn times_return_is_error(rv: i64) -> bool { rv == -1 }

#[cfg(test)]
mod tests {
    use super::*;

    fn field(b: &[u8; RUSAGE_BYTES], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    #[test]
    fn getrusage_rejects_the_kernel_internal_both_selector() {
        assert!(getrusage_who_valid(RUSAGE_SELF));
        assert!(getrusage_who_valid(RUSAGE_CHILDREN));
        assert!(getrusage_who_valid(RUSAGE_THREAD));
        assert!(!getrusage_who_valid(RUSAGE_BOTH));
        assert!(!getrusage_who_valid(2));
        assert!(!getrusage_who_valid(i32::MIN));
    }

    #[test]
    fn every_tracked_counter_lands_at_its_abi_offset() {
        let r = Rusage {
            utime_ns: 3_250_000_000, stime_ns: 1_000_001_000,
            maxrss_kb: 4096, minflt: 11, majflt: 3,
            inblock: 40, oublock: 8, nvcsw: 77, nivcsw: 5,
        };
        let b = r.encode();
        assert_eq!(field(&b, OFF_UTIME_SEC), 3);
        assert_eq!(field(&b, OFF_UTIME_USEC), 250_000);
        assert_eq!(field(&b, OFF_STIME_SEC), 1);
        assert_eq!(field(&b, OFF_STIME_USEC), 1);
        assert_eq!(field(&b, OFF_MAXRSS), 4096);
        assert_eq!(field(&b, OFF_MINFLT), 11);
        assert_eq!(field(&b, OFF_MAJFLT), 3);
        assert_eq!(field(&b, OFF_INBLOCK), 40);
        assert_eq!(field(&b, OFF_OUBLOCK), 8);
        assert_eq!(field(&b, OFF_NVCSW), 77);
        assert_eq!(field(&b, OFF_NIVCSW), 5);
    }

    #[test]
    fn unsourced_members_stay_zero_and_nothing_overlaps() {
        let b = Rusage { utime_ns: 1, stime_ns: 1, maxrss_kb: 1, minflt: 1,
                         majflt: 1, inblock: 1, oublock: 1, nvcsw: 1, nivcsw: 1 }.encode();
        // ru_ixrss/ru_idrss/ru_isrss, ru_nswap, ru_msgsnd/ru_msgrcv/ru_nsignals.
        for off in [40, 48, 56, 80, 104, 112, 120] {
            assert_eq!(field(&b, off), 0, "offset {off} must stay zero");
        }
        assert_eq!(b.len(), 144);
    }

    #[test]
    fn both_sums_counters_but_takes_the_max_high_water_mark() {
        let own      = Rusage { utime_ns: 10, stime_ns: 20, maxrss_kb: 100, minflt: 1, majflt: 2, inblock: 3, oublock: 4, nvcsw: 5, nivcsw: 6 };
        let children = Rusage { utime_ns: 1,  stime_ns: 2,  maxrss_kb: 900, minflt: 7, majflt: 8, inblock: 9, oublock: 10, nvcsw: 11, nivcsw: 12 };
        let b = Rusage::both(own, children);
        assert_eq!(b.utime_ns, 11);
        assert_eq!(b.stime_ns, 22);
        assert_eq!(b.maxrss_kb, 900);
        assert_eq!(b.minflt, 8);
        assert_eq!(b.majflt, 10);
        assert_eq!(b.inblock, 12);
        assert_eq!(b.oublock, 14);
        assert_eq!(b.nvcsw, 16);
        assert_eq!(b.nivcsw, 18);
    }

    #[test]
    fn block_io_counters_are_512_byte_sectors_not_byte_counts() {
        assert_eq!(bytes_to_blocks(0), 0);
        assert_eq!(bytes_to_blocks(511), 0);
        assert_eq!(bytes_to_blocks(512), 1);
        assert_eq!(bytes_to_blocks(4096), 8);
    }

    #[test]
    fn tms_members_land_in_declaration_order_as_four_longs() {
        let b = Tms { utime_ticks: 11, stime_ticks: 22, cutime_ticks: 33, cstime_ticks: 44 }.encode();
        assert_eq!(b.len(), TMS_BYTES);
        let at = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        assert_eq!((at(0), at(1), at(2), at(3)), (11, 22, 33, 44));
    }

    #[test]
    fn times_with_a_null_buffer_succeeds_rather_than_faulting() {
        // The classic divergence: `times(NULL)` is legal and still returns the
        // tick count, so a NULL pointer must skip the copy-out, not EFAULT.
        assert!(!times_wants_tms(0));
        assert!(times_wants_tms(0x7fff_0000));
    }

    #[test]
    fn only_the_exact_minus_one_tick_count_reads_as_an_error() {
        assert!(times_return_is_error(-1));
        assert!(!times_return_is_error(0));
        assert!(!times_return_is_error(-2));
        // A tick count deep in the range a plain errno check would reject is
        // still a valid result, because the return is forced successful.
        assert!(!times_return_is_error(-4095i64 & 0x7fff_ffff_ffff_ffff));
        assert!(!times_return_is_error(i64::MAX));
    }
}
