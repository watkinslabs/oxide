//! `struct timespec64` — the VFS wall-clock
//! timestamp representation.
//!
//! File times are `time64_t tv_sec` (a SIGNED 64-bit second count)
//! plus an unsigned sub-second `tv_nsec` in `[0, NSEC_PER_SEC)`, and the inode
//! keeps them as the `i_atime_sec`/`i_atime_nsec` field pair.
//! Pre-epoch times are ordinary and legal: timestamp validation
//! checks only `tv_nsec`, never `tv_sec`, so
//! `utimensat(..., {.tv_sec = -1000000})` succeeds — `tar`/`rsync`/`cp -p`
//! restoring pre-1970 archives depend on it.
//!
//! A single 64-bit nanosecond scalar CANNOT carry this contract: it spans only
//! 1677..2262, while the default superblock window is `TIME64_MIN..TIME64_MAX`
//! and ext4's own max stored timestamp reaches year 2446. Hence the split
//! pair, not `i64` ns.
//!
//! Field order is `sec` then `nsec` so the derived `Ord` IS
//! `timespec64_compare` — seconds first (signed), then the sub-second field
//! (which the [`Timespec64::new`] normalization keeps in range).

/// Nanoseconds per second as the sub-second field's own type. # C: O(1)
pub const NSEC_PER_SEC: u32 = 1_000_000_000;

/// Nanoseconds per second in the seconds field's type, for scale conversions.
/// # C: O(1)
pub const NSEC_PER_SEC_I64: i64 = NSEC_PER_SEC as i64;

/// Microseconds per second — the `utimes`/`futimesat` `struct timeval` scale.
/// # C: O(1)
pub const USEC_PER_SEC: i64 = 1_000_000;

/// Nanoseconds per microsecond — widens a `timeval` sub-second field to
/// `timespec64`. # C: O(1)
pub const NSEC_PER_USEC: i64 = 1_000;

/// `24*60*60` — the relatime staleness window in seconds
/// (`relatime_need_update`'s one-day threshold). # C: O(1)
pub const SECS_PER_DAY: i64 = 24 * 60 * 60;

/// `struct timespec64` — a wall-clock instant relative to the Unix epoch.
/// `sec` is signed (pre-1970 is legal); `nsec` is always in
/// `[0, NSEC_PER_SEC)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
pub struct Timespec64 {
    pub sec: i64,
    pub nsec: u32,
}

impl Timespec64 {
    /// The epoch itself (1970-01-01T00:00:00Z). NOT an "absent" sentinel — it
    /// is an ordinary, representable time. # C: O(1)
    pub const ZERO: Self = Self { sec: 0, nsec: 0 };

    /// Widest representable instant (`TIME64_MIN`/`TIME64_MAX`). # C: O(1)
    pub const MIN: Self = Self { sec: i64::MIN, nsec: 0 };
    /// See [`Self::MIN`]. # C: O(1)
    pub const MAX: Self = Self { sec: i64::MAX, nsec: NSEC_PER_SEC - 1 };

    /// Construct from an already-normalized pair. `nsec` at or above
    /// `NSEC_PER_SEC` would break the derived ordering, so it is folded into
    /// `sec` here rather than trusted. # C: O(1)
    pub const fn new(sec: i64, nsec: u32) -> Self {
        if nsec < NSEC_PER_SEC { return Self { sec, nsec }; }
        let carry = (nsec / NSEC_PER_SEC) as i64;
        Self { sec: sec.saturating_add(carry), nsec: nsec % NSEC_PER_SEC }
    }

    /// Construct from a whole second count. # C: O(1)
    pub const fn from_secs(sec: i64) -> Self { Self { sec, nsec: 0 } }

    /// Construct from a signed nanosecond count relative to the epoch, using
    /// EUCLIDEAN division so a negative input floors toward `-inf` and leaves
    /// `nsec` non-negative — truncating division would produce a negative
    /// remainder, which POSIX forbids in `tv_nsec` and which the derived
    /// ordering could not represent. # C: O(1)
    pub const fn from_ns(ns: i64) -> Self {
        Self { sec: ns.div_euclid(NSEC_PER_SEC_I64), nsec: ns.rem_euclid(NSEC_PER_SEC_I64) as u32 }
    }

    /// From an UNSIGNED nanosecond clock reading — the shape
    /// `inode_times::realtime_now_ns` returns. A wall clock is post-epoch by
    /// construction, and `u64::MAX` ns is only year 2554, so the seconds
    /// quotient always fits `i64` and no saturation arises. # C: O(1)
    pub const fn from_clock_ns(ns: u64) -> Self {
        Self { sec: (ns / NSEC_PER_SEC as u64) as i64, nsec: (ns % NSEC_PER_SEC as u64) as u32 }
    }

    /// Nanoseconds since the epoch, or `None` when the instant is outside the
    /// ~584-year window a 64-bit nanosecond scalar can express. # C: O(1)
    pub const fn checked_to_ns(self) -> Option<i64> {
        match self.sec.checked_mul(NSEC_PER_SEC_I64) {
            Some(v) => v.checked_add(self.nsec as i64),
            None    => None,
        }
    }

    /// Nanoseconds since the epoch, pinned to `i64::MIN`/`i64::MAX` outside the
    /// representable window. For interfaces whose own unit is ns; the stored
    /// timestamp keeps full range regardless. # C: O(1)
    pub const fn to_ns_saturating(self) -> i64 {
        match self.checked_to_ns() {
            Some(v) => v,
            None    => if self.sec < 0 { i64::MIN } else { i64::MAX },
        }
    }

    /// Whole seconds between `self` and an earlier `rhs`, saturating instead of
    /// overflowing (Linux `(long)(now.tv_sec - atime.tv_sec)`). # C: O(1)
    pub const fn secs_since(self, rhs: Self) -> i64 { self.sec.saturating_sub(rhs.sec) }

    /// Clamp the seconds field to `[min, max]` (Linux `timestamp_truncate`'s
    /// `clamp(t.tv_sec, sb->s_time_min, sb->s_time_max)`), zeroing the
    /// sub-second field when the clamp bites — an out-of-window instant pins to
    /// the boundary SECOND, not to a sub-second offset past it. # C: O(1)
    pub const fn clamp_secs(self, min: i64, max: i64) -> Self {
        if self.sec > max { return Self { sec: max, nsec: 0 }; }
        if self.sec < min { return Self { sec: min, nsec: 0 }; }
        self
    }

    /// Floor the sub-second field to a multiple of `gran` ns (Linux
    /// `timestamp_truncate`: `t.tv_nsec -= t.tv_nsec % gran`). `gran <= 1` is
    /// the identity; `gran >= NSEC_PER_SEC` floors to a whole second. Confined
    /// to `nsec`, so it never moves a pre-epoch instant the wrong way — the
    /// seconds field is already the floor. # C: O(1)
    pub const fn floor_gran(self, gran: u32) -> Self {
        if gran <= 1 { return self; }
        if gran >= NSEC_PER_SEC { return Self { sec: self.sec, nsec: 0 }; }
        Self { sec: self.sec, nsec: self.nsec - self.nsec % gran }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_ns_floors_negatives_euclidean() {
        // -1.5s is 1969-12-31T23:59:58.5 — sec floors to -2, nsec stays
        // non-negative. Truncating division would give (-1, -500_000_000).
        assert_eq!(Timespec64::from_ns(-1_500_000_000), Timespec64 { sec: -2, nsec: 500_000_000 });
        assert_eq!(Timespec64::from_ns(-1), Timespec64 { sec: -1, nsec: 999_999_999 });
        assert_eq!(Timespec64::from_ns(0), Timespec64::ZERO);
        assert_eq!(Timespec64::from_ns(1_500_000_000), Timespec64 { sec: 1, nsec: 500_000_000 });
    }

    #[test]
    fn ns_round_trip_within_window() {
        for ns in [-9_223_372_036_000_000_000i64, -1_000_000_001, -1, 0, 1, 1_700_000_000_000_000_000] {
            assert_eq!(Timespec64::from_ns(ns).checked_to_ns(), Some(ns));
        }
    }

    #[test]
    fn ns_scalar_cannot_hold_the_full_range() {
        // The exact reason the model is a split pair and not an `i64` of ns:
        // ext4's own `s_time_max` (year 2446) overflows a ns scalar.
        let ext4_max = Timespec64::from_secs(((1i64 << 34) - 1) + i32::MIN as i64);
        assert_eq!(ext4_max.checked_to_ns(), None);
        assert_eq!(ext4_max.to_ns_saturating(), i64::MAX);
        assert_eq!(Timespec64::MIN.to_ns_saturating(), i64::MIN);
    }

    #[test]
    fn ordering_is_timespec64_compare() {
        let pre = Timespec64 { sec: -1_000_000, nsec: 0 };
        let epoch = Timespec64::ZERO;
        let post = Timespec64 { sec: 1_700_000_000, nsec: 1 };
        assert!(pre < epoch && epoch < post);
        // The bug an unsigned model hides: as `u64` ns, `pre` is ~1.8e19 and
        // would compare GREATER than both.
        assert!(pre < post);
        assert!(Timespec64 { sec: 5, nsec: 1 } > Timespec64 { sec: 5, nsec: 0 });
        assert!(Timespec64 { sec: -5, nsec: 1 } > Timespec64 { sec: -5, nsec: 0 });
    }

    #[test]
    fn clamp_pins_to_boundary_second() {
        let (min, max) = (i32::MIN as i64, i32::MAX as i64);
        let old = Timespec64 { sec: -3_000_000_000, nsec: 7 };
        assert_eq!(old.clamp_secs(min, max), Timespec64 { sec: min, nsec: 0 });
        let far = Timespec64 { sec: 3_000_000_000, nsec: 7 };
        assert_eq!(far.clamp_secs(min, max), Timespec64 { sec: max, nsec: 0 });
        let inside = Timespec64 { sec: -1_000_000, nsec: 7 };
        assert_eq!(inside.clamp_secs(min, max), inside);
    }

    #[test]
    fn floor_gran_touches_only_the_subsecond_field() {
        let t = Timespec64 { sec: -1_000_000, nsec: 999_999_999 };
        assert_eq!(t.floor_gran(1), t);
        assert_eq!(t.floor_gran(NSEC_PER_SEC), Timespec64 { sec: -1_000_000, nsec: 0 });
        assert_eq!(t.floor_gran(1_000), Timespec64 { sec: -1_000_000, nsec: 999_999_000 });
    }

    #[test]
    fn secs_since_is_signed_and_saturating() {
        let atime = Timespec64 { sec: -1_000_000, nsec: 0 };
        let now = Timespec64 { sec: 0, nsec: 0 };
        assert_eq!(now.secs_since(atime), 1_000_000);
        // Backwards clock: negative, so the relatime day-window test fails.
        assert_eq!(atime.secs_since(now), -1_000_000);
        assert_eq!(Timespec64::MAX.secs_since(Timespec64::MIN), i64::MAX);
    }

    #[test]
    fn new_normalizes_an_overflowing_subsecond_field() {
        assert_eq!(Timespec64::new(5, NSEC_PER_SEC), Timespec64 { sec: 6, nsec: 0 });
        assert_eq!(Timespec64::new(-5, NSEC_PER_SEC + 7), Timespec64 { sec: -4, nsec: 7 });
    }
}
