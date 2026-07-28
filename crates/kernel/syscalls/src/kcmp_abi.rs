// kcmp(2) type vocabulary + result encoding, per Linux `kernel/kcmp.c` and
// `include/uapi/linux/kcmp.h`.
//
// Non-gated so a hosted `cargo test` actually runs these: every numbered slot
// file (`312_kcmp.rs` included) is behind `kernel_body.rs`'s
// `#[cfg(target_os = "oxide-kernel")]`, where a `#[cfg(test)] mod tests` would
// compile out silently.

/// `enum kcmp_type` — the ORDER is ABI. `KCMP_VM` is 1 and `KCMP_FILES` is 2;
/// swapping them makes every `kcmp` answer about address spaces report on
/// descriptor tables and vice versa, silently.
pub const KCMP_FILE:      u32 = 0;
pub const KCMP_VM:        u32 = 1;
pub const KCMP_FILES:     u32 = 2;
pub const KCMP_FS:        u32 = 3;
pub const KCMP_SIGHAND:   u32 = 4;
pub const KCMP_IO:        u32 = 5;
pub const KCMP_SYSVSEM:   u32 = 6;
pub const KCMP_EPOLL_TFD: u32 = 7;
/// `KCMP_TYPES` — first value outside the enum. Linux's `switch` default is
/// EINVAL, so this doubles as the validity bound.
pub const KCMP_TYPES:     u32 = 8;

/// Linux `kcmp_ptr` result encoding: `(t1 < t2) | ((t1 > t2) << 1)`.
///
/// NEVER negative: a raw syscall return in `[-4095,-1]` is read by glibc/musl
/// as `-errno`, so "less than" must be 1, not -1. systemd's `same_fd()` does
/// `r = kcmp(...); if (r >= 0) return !r;` and only reaches its fstat fallback
/// on a (spurious) error.
pub const KCMP_EQUAL:   i64 = 0;
pub const KCMP_LESS:    i64 = 1;
pub const KCMP_GREATER: i64 = 2;

/// True for a `type` value Linux's `switch` accepts. `type` is a C `int`, so
/// a negative value arrives here with its high bits set and lands outside.
/// # C: O(1)
pub fn type_is_known(ty: u32) -> bool { ty < KCMP_TYPES }

/// Linux `kcmp_ptr` ordering of two present resource ids. # C: O(1)
pub fn ptr_cmp(a: usize, b: usize) -> i64 {
    if a == b { KCMP_EQUAL } else if a < b { KCMP_LESS } else { KCMP_GREATER }
}

/// Ordering when a resource id may be absent — a task whose slot has already
/// been released during exit. Linux compares the raw pointer, and `NULL`
/// sorts below every real allocation. # C: O(1)
pub fn opt_cmp(a: Option<usize>, b: Option<usize>) -> i64 {
    match (a, b) {
        (Some(x), Some(y)) => ptr_cmp(x, y),
        (None,    None)    => KCMP_EQUAL,
        (None,    Some(_)) => KCMP_LESS,
        (Some(_), None)    => KCMP_GREATER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_numbering_matches_uapi_order() {
        // include/uapi/linux/kcmp.h — KCMP_VM precedes KCMP_FILES.
        assert_eq!(KCMP_FILE, 0);
        assert_eq!(KCMP_VM, 1);
        assert_eq!(KCMP_FILES, 2);
        assert_eq!(KCMP_FS, 3);
        assert_eq!(KCMP_SIGHAND, 4);
        assert_eq!(KCMP_IO, 5);
        assert_eq!(KCMP_SYSVSEM, 6);
        assert_eq!(KCMP_EPOLL_TFD, 7);
        assert_eq!(KCMP_TYPES, 8);
    }

    #[test]
    fn every_uapi_type_is_known_and_nothing_beyond_is() {
        for ty in 0..KCMP_TYPES { assert!(type_is_known(ty), "type {ty}"); }
        assert!(!type_is_known(KCMP_TYPES));
        assert!(!type_is_known(u32::MAX));
        // A negative C int reaches the kernel as a large u32.
        assert!(!type_is_known((-1i32) as u32));
    }

    #[test]
    fn results_are_never_negative() {
        for (a, b) in [(0usize, 0usize), (0, 1), (1, 0), (usize::MAX, 0), (0, usize::MAX)] {
            assert!(ptr_cmp(a, b) >= 0, "ptr_cmp({a},{b}) must not look like -errno");
        }
        for a in [None, Some(0usize), Some(usize::MAX)] {
            for b in [None, Some(0usize), Some(usize::MAX)] {
                assert!(opt_cmp(a, b) >= 0);
            }
        }
    }

    #[test]
    fn ordering_is_total_and_matches_linux_encoding() {
        assert_eq!(ptr_cmp(7, 7), KCMP_EQUAL);
        assert_eq!(ptr_cmp(1, 2), KCMP_LESS);
        assert_eq!(ptr_cmp(2, 1), KCMP_GREATER);
    }

    #[test]
    fn absent_resource_sorts_below_present() {
        assert_eq!(opt_cmp(None, Some(1)), KCMP_LESS);
        assert_eq!(opt_cmp(Some(1), None), KCMP_GREATER);
        assert_eq!(opt_cmp(None, None), KCMP_EQUAL);
    }

    #[test]
    fn ordering_is_antisymmetric_over_a_sample_grid() {
        let vals = [0usize, 1, 2, 4096, usize::MAX / 2, usize::MAX];
        for &a in &vals {
            for &b in &vals {
                let ab = ptr_cmp(a, b);
                let ba = ptr_cmp(b, a);
                if a == b { assert_eq!((ab, ba), (KCMP_EQUAL, KCMP_EQUAL)); }
                else { assert_eq!(ab + ba, KCMP_LESS + KCMP_GREATER); }
            }
        }
    }
}
