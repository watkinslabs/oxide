// The pure mode-combination decision `vfs_fallocate` makes before it touches
// the inode (Linux `fs/open.c:259-285`). The `FALLOC_FL_*` values themselves
// are shared UAPI in `vfs::uapi` — the filesystem backends decode the same
// `mode` word and must not carry a second copy of the numbers.

use syscall::errno::Errno;

pub use vfs::uapi::{FALLOC_FL_ALLOCATE_RANGE, FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE,
    FALLOC_FL_KEEP_SIZE, FALLOC_FL_MODE_MASK, FALLOC_FL_NO_HIDE_STALE, FALLOC_FL_PUNCH_HOLE,
    FALLOC_FL_UNSHARE_RANGE, FALLOC_FL_WRITE_ZEROES, FALLOC_FL_ZERO_RANGE};

/// Mode-combination gate from `vfs_fallocate` (Linux `fs/open.c:259-285`).
///
/// Every rejection here is `EOPNOTSUPP`, never `EINVAL`: `vfs_fallocate` spends
/// its single `EINVAL` on the `offset`/`len` range check and reports every
/// unrepresentable mode as "this combination is not supported", so a caller can
/// distinguish a bad range from an unimplemented feature. Modes are mutually
/// exclusive even though they are encoded as bits, hence the `match` on the
/// masked value rather than per-bit tests.
/// # C: O(1)
pub fn falloc_mode_ok(mode: u32) -> Result<(), Errno> {
    if mode & !(FALLOC_FL_MODE_MASK | FALLOC_FL_KEEP_SIZE) != 0 { return Err(Errno::Eopnotsupp); }
    match mode & FALLOC_FL_MODE_MASK {
        FALLOC_FL_ALLOCATE_RANGE | FALLOC_FL_UNSHARE_RANGE | FALLOC_FL_ZERO_RANGE => Ok(()),
        // Deallocating a range may never change `i_size`: the caller must say so.
        FALLOC_FL_PUNCH_HOLE =>
            if mode & FALLOC_FL_KEEP_SIZE == 0 { Err(Errno::Eopnotsupp) } else { Ok(()) },
        // These three each MOVE the file's end, so "keep the size" is a contradiction.
        FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE | FALLOC_FL_WRITE_ZEROES =>
            if mode & FALLOC_FL_KEEP_SIZE != 0 { Err(Errno::Eopnotsupp) } else { Ok(()) },
        // Two or more mode bits at once: no such operation exists.
        _ => Err(Errno::Eopnotsupp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bits above the defined byte, sampled where a 32-bit mode can carry junk.
    const HIGH_BITS: [u32; 8] = [0x100, 0x200, 0x8000, 0x1_0000, 0x100_0000,
        0x2000_0000, 0x8000_0000, 0xFFFF_FF00];

    fn ok(mode: u32)   { assert_eq!(falloc_mode_ok(mode), Ok(()),                    "mode {mode:#x} must be accepted"); }
    fn nosup(mode: u32) { assert_eq!(falloc_mode_ok(mode), Err(Errno::Eopnotsupp),   "mode {mode:#x} must be EOPNOTSUPP"); }

    #[test]
    fn mode_mask_matches_linux_composite() {
        assert_eq!(FALLOC_FL_MODE_MASK, 0xFA, "include/linux/falloc.h FALLOC_FL_MODE_MASK");
        assert_eq!(FALLOC_FL_MODE_MASK & FALLOC_FL_NO_HIDE_STALE, 0, "NO_HIDE_STALE is not a mode");
        assert_eq!(FALLOC_FL_MODE_MASK & FALLOC_FL_KEEP_SIZE, 0, "KEEP_SIZE is a flag, not a mode");
    }

    #[test]
    fn allocate_range_is_the_empty_mode() {
        assert_eq!(FALLOC_FL_ALLOCATE_RANGE, 0);
        ok(FALLOC_FL_ALLOCATE_RANGE);
        ok(FALLOC_FL_KEEP_SIZE);
    }

    #[test]
    fn every_single_mode_bit_gets_its_linux_answer() {
        ok(FALLOC_FL_ZERO_RANGE);
        ok(FALLOC_FL_UNSHARE_RANGE);
        ok(FALLOC_FL_COLLAPSE_RANGE);
        ok(FALLOC_FL_INSERT_RANGE);
        ok(FALLOC_FL_WRITE_ZEROES);
        // PUNCH_HOLE alone is the one mode that is invalid WITHOUT the flag.
        nosup(FALLOC_FL_PUNCH_HOLE);
        nosup(FALLOC_FL_NO_HIDE_STALE);
    }

    #[test]
    fn punch_hole_requires_keep_size() {
        nosup(FALLOC_FL_PUNCH_HOLE);
        ok(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE);
    }

    #[test]
    fn size_moving_modes_reject_keep_size() {
        for m in [FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE, FALLOC_FL_WRITE_ZEROES] {
            ok(m);
            nosup(m | FALLOC_FL_KEEP_SIZE);
        }
    }

    #[test]
    fn zero_and_unshare_range_accept_keep_size_either_way() {
        for m in [FALLOC_FL_ZERO_RANGE, FALLOC_FL_UNSHARE_RANGE] {
            ok(m);
            ok(m | FALLOC_FL_KEEP_SIZE);
        }
    }

    #[test]
    fn any_two_mode_bits_together_are_unsupported() {
        let modes = [FALLOC_FL_PUNCH_HOLE, FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_ZERO_RANGE,
            FALLOC_FL_INSERT_RANGE, FALLOC_FL_UNSHARE_RANGE, FALLOC_FL_WRITE_ZEROES];
        for (i, a) in modes.iter().enumerate() {
            for b in &modes[i + 1..] {
                nosup(a | b);
                nosup(a | b | FALLOC_FL_KEEP_SIZE);
            }
        }
    }

    #[test]
    fn no_hide_stale_is_never_accepted_in_any_company() {
        for m in 0u32..=0xFF {
            nosup(m | FALLOC_FL_NO_HIDE_STALE);
        }
    }

    #[test]
    fn undefined_high_bits_are_unsupported() {
        for hi in HIGH_BITS {
            for m in [FALLOC_FL_ALLOCATE_RANGE, FALLOC_FL_KEEP_SIZE, FALLOC_FL_ZERO_RANGE,
                      FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE] {
                nosup(m | hi);
            }
        }
    }

    /// `vfs_fallocate` reserves `EINVAL` for the range check; the mode gate must
    /// never produce it, or `posix_fallocate` would report the wrong failure.
    #[test]
    fn mode_gate_never_returns_einval() {
        for m in 0u32..=0xFFFF {
            assert_ne!(falloc_mode_ok(m), Err(Errno::Einval), "mode {m:#x}");
        }
        for hi in HIGH_BITS {
            for m in 0u32..=0xFF {
                assert_ne!(falloc_mode_ok(m | hi), Err(Errno::Einval), "mode {:#x}", m | hi);
            }
        }
    }

    /// The accepted set is exactly Linux's, enumerated over the whole low byte.
    #[test]
    fn accepted_low_byte_set_is_exactly_linux() {
        let accepted: alloc::vec::Vec<u32> = (0u32..=0xFF).filter(|m| falloc_mode_ok(*m).is_ok()).collect();
        assert_eq!(accepted, alloc::vec![
            FALLOC_FL_ALLOCATE_RANGE,
            FALLOC_FL_KEEP_SIZE,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            FALLOC_FL_COLLAPSE_RANGE,
            FALLOC_FL_ZERO_RANGE,
            FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
            FALLOC_FL_INSERT_RANGE,
            FALLOC_FL_UNSHARE_RANGE,
            FALLOC_FL_UNSHARE_RANGE | FALLOC_FL_KEEP_SIZE,
            FALLOC_FL_WRITE_ZEROES,
        ]);
    }
}
