// `RWF_*` per-I/O flags, the
// `kiocb_set_rw_flags()` admission ladder,
// and the `pos_from_hilo` offset rule shared by
// preadv/preadv2/pwritev/pwritev2.
//
// No target gate: the offset rule is arch-conditional, and the pre-fix x86_64
// branch used the 32-bit COMPAT hi/lo formula. That is invisible to any test
// placed inside the `oxide-kernel`-gated slot file, so it lives here.

use syscall::errno::Errno;

/// `RWF_HIPRI` — poll for completion. No-op on a synchronous backend; Linux
/// itself silently drops it whenever polling is impossible and never rejects
/// it, and it does NOT require `O_DIRECT` at the VFS layer.
pub const RWF_HIPRI:     u64 = 0x0000_0001;
/// `RWF_DSYNC` — per-write `O_DSYNC`.
pub const RWF_DSYNC:     u64 = 0x0000_0002;
/// `RWF_SYNC` — per-write `O_SYNC` (implies DSYNC).
pub const RWF_SYNC:      u64 = 0x0000_0004;
/// `RWF_NOWAIT` — never block; requires `FMODE_NOWAIT` on the description or
/// the call is `EOPNOTSUPP`.
pub const RWF_NOWAIT:    u64 = 0x0000_0008;
/// `RWF_APPEND` — force `IOCB_APPEND` for this operation; the supplied offset
/// is then IGNORED.
pub const RWF_APPEND:    u64 = 0x0000_0010;
/// `RWF_NOAPPEND` — clear `IOCB_APPEND` inherited from `O_APPEND` so the
/// supplied offset is honoured; `EPERM` if the INODE is append-only.
pub const RWF_NOAPPEND:  u64 = 0x0000_0020;
/// `RWF_ATOMIC` — torn-write-free; write-side only, needs
/// `FMODE_CAN_ATOMIC_WRITE`.
pub const RWF_ATOMIC:    u64 = 0x0000_0040;
/// `RWF_DONTCACHE` — drop the page cache behind the I/O; needs `FOP_DONTCACHE`.
pub const RWF_DONTCACHE: u64 = 0x0000_0080;
/// `RWF_NOSIGNAL` — suppress SIGPIPE on a broken pipe write.
pub const RWF_NOSIGNAL:  u64 = 0x0000_0100;
/// `RWF_SUPPORTED` — every other bit is
/// `EOPNOTSUPP`. The pre-fix constant was `0x1f`, which rejected the four flags
/// Linux has added since (NOAPPEND / ATOMIC / DONTCACHE / NOSIGNAL) with the
/// right errno by accident but for the wrong reason, and made NOAPPEND
/// unreachable.
pub const RWF_SUPPORTED: u64 = RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT
    | RWF_APPEND | RWF_NOAPPEND | RWF_ATOMIC | RWF_DONTCACHE | RWF_NOSIGNAL;

/// Direction of the operation the flags are being validated for — `RWF_ATOMIC`
/// is write-only.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RwDir { Read, Write }

/// Per-description capabilities `kiocb_set_rw_flags` consults.
#[derive(Copy, Clone, Debug, Default)]
pub struct RwCaps {
    /// `FMODE_NOWAIT` — the backend can complete without blocking or say EAGAIN.
    pub nowait: bool,
    /// `FMODE_CAN_ATOMIC_WRITE`.
    pub atomic_write: bool,
    /// `FOP_DONTCACHE`.
    pub dontcache: bool,
    /// `IOCB_APPEND` seeded from `O_APPEND` on the open file description.
    pub o_append: bool,
    /// `IS_APPEND(inode)` — the append-only INODE flag (chattr +a).
    pub inode_append_only: bool,
}

/// Resolved per-operation behaviour after a successful validation.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct RwEffect {
    /// Effective `IOCB_APPEND`: the offset argument must be replaced by i_size.
    pub append: bool,
    /// Effective `IOCB_NOWAIT`: return `EAGAIN` rather than sleep.
    pub nowait: bool,
    /// Effective `IOCB_DSYNC` (set by RWF_DSYNC and by RWF_SYNC).
    pub dsync: bool,
    /// Effective `IOCB_SYNC`.
    pub sync: bool,
}

/// `kiocb_set_rw_flags()` in Linux's exact
/// order. Every rejection is `EOPNOTSUPP` except the APPEND/NOAPPEND conflict
/// (`EINVAL`) and the append-only-inode override (`EPERM`).
///
/// Note `flags == 0` short-circuits before anything else, so a plain
/// `preadv2(..., 0)` behaves identically to `preadv` even on a description that
/// supports none of the capabilities. # C: O(1)
pub fn kiocb_set_rw_flags(flags: u64, dir: RwDir, caps: &RwCaps) -> Result<RwEffect, Errno> {
    if flags == 0 {
        return Ok(RwEffect { append: caps.o_append, ..RwEffect::default() });
    }
    if flags & !RWF_SUPPORTED != 0 { return Err(Errno::Eopnotsupp); }
    if flags & RWF_APPEND != 0 && flags & RWF_NOAPPEND != 0 { return Err(Errno::Einval); }
    if flags & RWF_NOWAIT != 0 && !caps.nowait { return Err(Errno::Eopnotsupp); }
    if flags & RWF_ATOMIC != 0 {
        if dir != RwDir::Write { return Err(Errno::Eopnotsupp); }
        if !caps.atomic_write { return Err(Errno::Eopnotsupp); }
    }
    if flags & RWF_DONTCACHE != 0 && !caps.dontcache { return Err(Errno::Eopnotsupp); }
    let mut eff = RwEffect {
        append: caps.o_append || flags & RWF_APPEND != 0,
        nowait: flags & RWF_NOWAIT != 0,
        dsync:  flags & (RWF_DSYNC | RWF_SYNC) != 0,
        sync:   flags & RWF_SYNC != 0,
    };
    if flags & RWF_NOAPPEND != 0 && eff.append {
        // Clearing IOCB_APPEND on an append-only INODE is EPERM, not a silent
        // downgrade.
        if caps.inode_append_only { return Err(Errno::Eperm); }
        eff.append = false;
    }
    Ok(eff)
}

/// `pos_from_hilo(pos_h, pos_l)`:
/// `(((loff_t)high << 32) << 32) | low`. On a 64-bit kernel the double shift
/// discards `high` entirely, so the NATIVE syscall takes the full offset in
/// `pos_l` alone and `pos_h` is dead — glibc's `LO_HI_LONG` passes one argument
/// on a 64-bit target and leaves the `pos_h` register uninitialised.
///
/// Only the 32-bit COMPAT entries (`COMPAT_SYSCALL_DEFINE5(preadv)`
/// and friends) use `((loff_t)pos_high << 32) | pos_low`.
/// Applying the compat formula on x86_64 — which is what the pre-fix slot did —
/// truncates the offset to 32 bits AND ORs in whatever junk the caller happened
/// to leave in `r8`. Both arches are native 64-bit here, so there is one rule.
/// # C: O(1)
pub fn pos_from_hilo(pos_l: u64, pos_h: u64) -> i64 {
    let _ = pos_h; // shifted out by `(high << 32) << 32` on a 64-bit long
    pos_l as i64
}

/// `preadv2`/`pwritev2` current-offset escape: `pos == -1` EXACTLY means "use
/// and advance `f_pos`", i.e. behave
/// as `readv`/`writev`. Any other negative `pos` is `EINVAL` from `do_preadv`,
/// checked BEFORE the fd lookup — so a bad fd with a bad offset
/// reports EINVAL, not EBADF. The non-`2` `preadv`/`pwritev` have no such
/// escape: `-1` there is just a negative offset. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PreadvPos { CurrentOffset, At(u64), Invalid }

/// Classify the resolved `pos` for a `preadv`-family call. `v2` selects whether
/// the `pos == -1` escape applies. # C: O(1)
pub fn preadv_pos(pos: i64, v2: bool) -> PreadvPos {
    if v2 && pos == -1 { return PreadvPos::CurrentOffset; }
    if pos < 0 { return PreadvPos::Invalid; }
    PreadvPos::At(pos as u64)
}

/// `MAX_RW_COUNT` — `INT_MAX & PAGE_MASK`. The
/// iovec importer silently TRUNCATES the tail of a vector whose running total
/// crosses it rather than erroring.
pub const MAX_RW_COUNT: u64 = (i32::MAX as u64) & !0xfff;
/// `UIO_MAXIOV` — `iovcnt` above this is
/// `EINVAL` ; `iovcnt == 0` is a valid zero-length
/// operation returning 0, NOT an error.
pub const UIO_MAXIOV: u64 = 1024;

/// What the iovec importer does with one segment, given the bytes already
/// accepted from earlier segments.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IovSeg {
    /// Zero-length segment: contributes nothing, walk continues.
    Skip,
    /// Accept this many bytes (may be less than the segment's own length when
    /// the running total reaches `MAX_RW_COUNT`).
    Take(u64),
    /// The running total already sits at `MAX_RW_COUNT`; the rest of the vector
    /// is dropped WITHOUT an error.
    Stop,
}

/// One segment of the `import_iovec` rule set, shared by every
/// `readv`/`writev`/`preadv*`/`pwritev*` entry so the two directions cannot
/// drift apart.
///
/// Two rules are easy to omit and both were missing on the write side: a
/// segment whose length is negative when read as `ssize_t` is `EINVAL` (it is
/// NOT treated as a huge unsigned length), and the running total TRUNCATES at
/// `MAX_RW_COUNT` instead of erroring — a vector totalling more than 2 GiB is a
/// short transfer, never `EINVAL`. # C: O(1)
pub fn iov_import_seg(len: u64, total: u64) -> Result<IovSeg, Errno> {
    if (len as i64) < 0 { return Err(Errno::Einval); }
    if len == 0 { return Ok(IovSeg::Skip); }
    let room = MAX_RW_COUNT.saturating_sub(total);
    if room == 0 { return Ok(IovSeg::Stop); }
    Ok(IovSeg::Take(len.min(room)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 64-bit rule: the offset is `pos_l`, and `pos_h` is IGNORED. A test
    /// that pins this is the whole point of the module — the pre-fix x86_64
    /// branch OR'd `pos_h << 32` in, so a caller leaving junk in the `pos_h`
    /// register read at a wild offset, and any file offset above 4 GiB was
    /// truncated. # C: O(1)
    #[test]
    fn pos_from_hilo_ignores_pos_h_on_64bit() {
        assert_eq!(pos_from_hilo(0, 0), 0);
        assert_eq!(pos_from_hilo(4096, 0), 4096);
        // Junk in pos_h must not perturb the result.
        for junk in [1u64, 0xffff_ffff, 0xdead_beef_dead_beef, u64::MAX] {
            assert_eq!(pos_from_hilo(4096, junk), 4096, "pos_h {junk:#x} must be ignored");
        }
        // A > 4 GiB offset survives intact (the compat formula truncated it).
        let big = 0x1_0000_5000u64;
        assert_eq!(pos_from_hilo(big, 0), big as i64);
        assert_eq!(pos_from_hilo(big, 0xffff_ffff), big as i64);
        // -1 must round-trip so the preadv2 current-offset escape is reachable.
        assert_eq!(pos_from_hilo(u64::MAX, 0), -1);
    }

    /// `pos == -1` is the current-offset escape for the `2` variants only; any
    /// other negative offset is EINVAL for all four. # C: O(1)
    #[test]
    fn preadv_pos_classification() {
        assert_eq!(preadv_pos(-1, true), PreadvPos::CurrentOffset);
        assert_eq!(preadv_pos(-1, false), PreadvPos::Invalid);
        for bad in [-2i64, -4096, i64::MIN] {
            assert_eq!(preadv_pos(bad, true), PreadvPos::Invalid, "{bad}");
            assert_eq!(preadv_pos(bad, false), PreadvPos::Invalid, "{bad}");
        }
        assert_eq!(preadv_pos(0, true), PreadvPos::At(0));
        assert_eq!(preadv_pos(1 << 40, false), PreadvPos::At(1 << 40));
    }

    /// `RWF_SUPPORTED` is the full nine-flag set; anything outside it is
    /// EOPNOTSUPP, and a zero flags word never fails. # C: O(1)
    #[test]
    fn unsupported_flag_bits_are_eopnotsupp() {
        assert_eq!(RWF_SUPPORTED, 0x1ff);
        let caps = RwCaps::default();
        assert!(kiocb_set_rw_flags(0, RwDir::Read, &caps).is_ok());
        for bad in [0x200u64, 0x400, 0x8000_0000, 1u64 << 63] {
            assert_eq!(kiocb_set_rw_flags(bad, RwDir::Read, &caps), Err(Errno::Eopnotsupp), "{bad:#x}");
            assert_eq!(kiocb_set_rw_flags(bad | RWF_HIPRI, RwDir::Write, &caps),
                Err(Errno::Eopnotsupp), "{bad:#x}");
        }
        // HIPRI/DSYNC/SYNC need no capability at all.
        for f in [RWF_HIPRI, RWF_DSYNC, RWF_SYNC, RWF_HIPRI | RWF_DSYNC | RWF_SYNC] {
            assert!(kiocb_set_rw_flags(f, RwDir::Read, &caps).is_ok(), "{f:#x}");
        }
    }

    /// `RWF_NOWAIT` on a description without `FMODE_NOWAIT` is EOPNOTSUPP —
    /// NOT silently accepted and then blocked on. An accept-and-block would be
    /// the real bug: a caller that asked never to wait would wait. # C: O(1)
    #[test]
    fn nowait_requires_the_capability() {
        let no = RwCaps::default();
        assert_eq!(kiocb_set_rw_flags(RWF_NOWAIT, RwDir::Read, &no), Err(Errno::Eopnotsupp));
        let yes = RwCaps { nowait: true, ..RwCaps::default() };
        let eff = kiocb_set_rw_flags(RWF_NOWAIT, RwDir::Read, &yes).unwrap();
        assert!(eff.nowait, "the capability must actually take effect");
        // ATOMIC is write-only and needs its own capability.
        assert_eq!(kiocb_set_rw_flags(RWF_ATOMIC, RwDir::Read, &yes), Err(Errno::Eopnotsupp));
        assert_eq!(kiocb_set_rw_flags(RWF_ATOMIC, RwDir::Write, &yes), Err(Errno::Eopnotsupp));
        let aw = RwCaps { atomic_write: true, ..RwCaps::default() };
        assert!(kiocb_set_rw_flags(RWF_ATOMIC, RwDir::Write, &aw).is_ok());
        // DONTCACHE needs FOP_DONTCACHE.
        assert_eq!(kiocb_set_rw_flags(RWF_DONTCACHE, RwDir::Read, &no), Err(Errno::Eopnotsupp));
        assert!(kiocb_set_rw_flags(RWF_DONTCACHE, RwDir::Read,
            &RwCaps { dontcache: true, ..RwCaps::default() }).is_ok());
    }

    /// APPEND/NOAPPEND: mutually exclusive (EINVAL), APPEND forces the offset
    /// to be ignored, NOAPPEND clears an inherited `O_APPEND`, and doing so on
    /// an append-only INODE is EPERM. # C: O(1)
    #[test]
    fn append_and_noappend_interaction() {
        let plain = RwCaps::default();
        assert_eq!(kiocb_set_rw_flags(RWF_APPEND | RWF_NOAPPEND, RwDir::Write, &plain),
            Err(Errno::Einval));
        assert!(kiocb_set_rw_flags(RWF_APPEND, RwDir::Write, &plain).unwrap().append);
        // O_APPEND alone already forces append, even with flags == 0.
        let oa = RwCaps { o_append: true, ..RwCaps::default() };
        assert!(kiocb_set_rw_flags(0, RwDir::Write, &oa).unwrap().append);
        assert!(!kiocb_set_rw_flags(RWF_NOAPPEND, RwDir::Write, &oa).unwrap().append);
        // ... unless the inode itself is append-only.
        let ao = RwCaps { o_append: true, inode_append_only: true, ..RwCaps::default() };
        assert_eq!(kiocb_set_rw_flags(RWF_NOAPPEND, RwDir::Write, &ao), Err(Errno::Eperm));
        // NOAPPEND on a non-append description is a no-op, not an error.
        assert!(!kiocb_set_rw_flags(RWF_NOAPPEND, RwDir::Write, &plain).unwrap().append);
        // RWF_SYNC implies DSYNC.
        let eff = kiocb_set_rw_flags(RWF_SYNC, RwDir::Write, &plain).unwrap();
        assert!(eff.sync && eff.dsync);
        let eff = kiocb_set_rw_flags(RWF_DSYNC, RwDir::Write, &plain).unwrap();
        assert!(eff.dsync && !eff.sync);
    }

    /// The two ABI limits: `MAX_RW_COUNT` is page-aligned `INT_MAX`, and
    /// `UIO_MAXIOV` is 1024. # C: O(1)
    #[test]
    fn abi_limits() {
        assert_eq!(MAX_RW_COUNT, 0x7fff_f000);
        assert_eq!(UIO_MAXIOV, 1024);
    }

    /// A segment length that is negative as `ssize_t` is `EINVAL` — NOT a
    /// nearly-2^64-byte transfer. The write side skipped this rule entirely
    /// and passed the raw `u64` to the usercopy validator, where the only
    /// thing standing between a `-1` length and a wild range was that
    /// validator's own bounds check. # C: O(1)
    #[test]
    fn negative_segment_length_is_einval() {
        for bad in [u64::MAX, 1u64 << 63, (i64::MIN as u64), 0xffff_ffff_ffff_f000] {
            assert_eq!(iov_import_seg(bad, 0), Err(Errno::Einval), "{bad:#x}");
            // Still EINVAL when earlier segments already contributed bytes:
            // the rule is per-segment, not a property of the running total.
            assert_eq!(iov_import_seg(bad, 4096), Err(Errno::Einval), "{bad:#x}");
        }
        // The largest non-negative length is legal and simply clamps.
        assert_eq!(iov_import_seg(i64::MAX as u64, 0), Ok(IovSeg::Take(MAX_RW_COUNT)));
    }

    /// The running total TRUNCATES at `MAX_RW_COUNT`; it never errors. A vector
    /// totalling more than the cap is a SHORT transfer, so the tail segments
    /// are dropped silently once the cap is reached. # C: O(1)
    #[test]
    fn total_truncates_at_max_rw_count_and_never_errors() {
        // Wholly below the cap: taken in full.
        assert_eq!(iov_import_seg(4096, 0), Ok(IovSeg::Take(4096)));
        assert_eq!(iov_import_seg(4096, MAX_RW_COUNT - 8192), Ok(IovSeg::Take(4096)));
        // Straddling the cap: only the room that is left.
        assert_eq!(iov_import_seg(4096, MAX_RW_COUNT - 1000), Ok(IovSeg::Take(1000)));
        assert_eq!(iov_import_seg(MAX_RW_COUNT, 1), Ok(IovSeg::Take(MAX_RW_COUNT - 1)));
        // At the cap: the rest of the vector is dropped, WITHOUT an error.
        assert_eq!(iov_import_seg(4096, MAX_RW_COUNT), Ok(IovSeg::Stop));
        assert_eq!(iov_import_seg(1, u64::MAX), Ok(IovSeg::Stop));
        // Zero-length segments contribute nothing and never stop the walk, even
        // once the cap has been reached.
        assert_eq!(iov_import_seg(0, 0), Ok(IovSeg::Skip));
        assert_eq!(iov_import_seg(0, MAX_RW_COUNT), Ok(IovSeg::Skip));
    }

    /// Walking a whole vector through the rule reproduces the observable
    /// contract: the returned count is the clamp, not an error, and the
    /// accepted total never exceeds `MAX_RW_COUNT` no matter the shape.
    /// # C: O(n)
    #[test]
    fn vector_walk_totals_are_capped() {
        fn walk(lens: &[u64]) -> Result<u64, Errno> {
            let mut total = 0u64;
            for &l in lens {
                match iov_import_seg(l, total)? {
                    IovSeg::Skip    => continue,
                    IovSeg::Stop    => break,
                    IovSeg::Take(n) => total += n,
                }
            }
            Ok(total)
        }
        assert_eq!(walk(&[0, 0, 0]), Ok(0));
        assert_eq!(walk(&[10, 0, 20]), Ok(30));
        // Three near-cap segments: the total stops exactly at the cap.
        let big = MAX_RW_COUNT / 2;
        assert_eq!(walk(&[big, big, big]), Ok(MAX_RW_COUNT));
        // A negative length anywhere fails the whole import.
        assert_eq!(walk(&[10, u64::MAX, 10]), Err(Errno::Einval));
    }
}
