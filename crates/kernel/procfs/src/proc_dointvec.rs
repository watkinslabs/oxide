//! `proc_dointvec` / `proc_dointvec_minmax` write validation (Linux
//! `kernel/sysctl.c` + `fs/proc/proc_sysctl.c`). Pure and host-testable: the
//! integer parse + range-check a writer's bytes go through before a bounded
//! `/proc/sys/*` integer leaf accepts a store. A `SysctlInode` carrying
//! `Some((min,max))` rejects an out-of-range or non-integer write with
//! `EINVAL`, exactly like `proc_dointvec_minmax` (whereas an unbounded
//! `proc_dointvec` slot — `None` — accepts any byte payload).
//!
//! Kept un-`cfg`-gated (unlike `sysctl`/`ctl`) so the validation contract is
//! covered by `cargo test -p procfs` on the host.

/// Validate a `proc_dointvec_minmax` write. Linux strips surrounding
/// whitespace/newline, parses each whitespace-separated token as a signed
/// decimal, and requires every value within the inclusive `[min, max]` window.
/// An empty payload or any non-decimal / out-of-range token → `Err(())`
/// (the caller maps it to `EINVAL`). # C: O(len)
pub fn validate_intvec(src: &[u8], min: i64, max: i64) -> Result<(), ()> {
    let s = core::str::from_utf8(src).map_err(|_| ())?;
    let mut any = false;
    for tok in s.split_ascii_whitespace() {
        any = true;
        let v: i64 = tok.parse().map_err(|_| ())?;
        if v < min || v > max { return Err(()); }
    }
    if any { Ok(()) } else { Err(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_range_ok() {
        assert!(validate_intvec(b"1\n", 0, 2).is_ok());
        assert!(validate_intvec(b"0", 0, 2).is_ok());
        assert!(validate_intvec(b"2\n", 0, 2).is_ok());
        assert!(validate_intvec(b"  60 \n", 0, 200).is_ok());
    }

    #[test]
    fn out_of_range_rejected() {
        assert!(validate_intvec(b"3\n", 0, 2).is_err());
        assert!(validate_intvec(b"-1\n", 0, 2).is_err());
        assert!(validate_intvec(b"201\n", 0, 200).is_err());
    }

    #[test]
    fn negative_allowed_when_min_negative() {
        // perf_event_paranoid: -1..=4.
        assert!(validate_intvec(b"-1\n", -1, 4).is_ok());
        assert!(validate_intvec(b"-2\n", -1, 4).is_err());
    }

    #[test]
    fn non_integer_rejected() {
        assert!(validate_intvec(b"abc\n", 0, 10).is_err());
        assert!(validate_intvec(b"1.5\n", 0, 10).is_err());
        assert!(validate_intvec(b"0x1\n", 0, 10).is_err());
    }

    #[test]
    fn empty_rejected() {
        assert!(validate_intvec(b"", 0, 10).is_err());
        assert!(validate_intvec(b"   \n", 0, 10).is_err());
    }

    #[test]
    fn multi_value_each_checked() {
        // proc_dointvec_minmax applies the window to every value in the vector.
        assert!(validate_intvec(b"1 2 3\n", 0, 3).is_ok());
        assert!(validate_intvec(b"1 2 9\n", 0, 3).is_err());
    }
}
