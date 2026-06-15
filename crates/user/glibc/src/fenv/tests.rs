//! fenv hosted differential tests (docs/59§7). On x86_64/aarch64 these drive
//! the real FP-env registers via the per-arch backend; round-trip + flag
//! semantics are checked against the C99 contract (and indirectly the host
//! libc, which shares the register layout). Round-mode/exception save+restore
//! must not leave the FP env perturbed for sibling tests, so each test
//! restores round-to-nearest + clears flags at the end.
use super::*;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn clear_test_roundtrip() {
    feclearexcept(FE_ALL_EXCEPT);
    assert_eq!(fetestexcept(FE_ALL_EXCEPT), 0);
    feraiseexcept(FE_INVALID | FE_INEXACT);
    assert_eq!(fetestexcept(FE_INVALID), FE_INVALID);
    assert_eq!(fetestexcept(FE_INEXACT), FE_INEXACT);
    assert_eq!(fetestexcept(FE_OVERFLOW), 0);
    feclearexcept(FE_INVALID);
    assert_eq!(fetestexcept(FE_INVALID), 0);
    assert_eq!(fetestexcept(FE_INEXACT), FE_INEXACT);
    feclearexcept(FE_ALL_EXCEPT);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn rounding_all_four() {
    let modes = [FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO];
    for &m in &modes {
        assert_eq!(fesetround(m), 0, "fesetround({m:#x}) failed");
        assert_eq!(fegetround(), m, "fegetround mismatch after set {m:#x}");
    }
    // invalid mode rejected, round unchanged.
    fesetround(FE_TONEAREST);
    assert_ne!(fesetround(0x12345), 0);
    assert_eq!(fegetround(), FE_TONEAREST);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn exceptflag_store_restore() {
    feclearexcept(FE_ALL_EXCEPT);
    feraiseexcept(FE_OVERFLOW | FE_UNDERFLOW);
    let mut saved: fexcept_t = 0;
    assert_eq!(fegetexceptflag(&mut saved, FE_ALL_EXCEPT), 0);
    feclearexcept(FE_ALL_EXCEPT);
    assert_eq!(fetestexcept(FE_ALL_EXCEPT), 0);
    assert_eq!(fesetexceptflag(&saved, FE_ALL_EXCEPT), 0);
    assert_eq!(fetestexcept(FE_OVERFLOW), FE_OVERFLOW);
    assert_eq!(fetestexcept(FE_UNDERFLOW), FE_UNDERFLOW);
    // fetestexceptflag inspects the stored value, not live state.
    assert_eq!(fetestexceptflag(&saved, FE_OVERFLOW), FE_OVERFLOW);
    feclearexcept(FE_ALL_EXCEPT);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn env_save_restore() {
    feclearexcept(FE_ALL_EXCEPT);
    fesetround(FE_TONEAREST);
    let mut env: fenv_t = unsafe { core::mem::zeroed() };
    assert_eq!(fegetenv(&mut env), 0);
    // perturb, then restore.
    fesetround(FE_UPWARD);
    feraiseexcept(FE_INEXACT);
    assert_eq!(fesetenv(&env), 0);
    assert_eq!(fegetround(), FE_TONEAREST);
    feclearexcept(FE_ALL_EXCEPT);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn hold_update_env() {
    feclearexcept(FE_ALL_EXCEPT);
    let mut env: fenv_t = unsafe { core::mem::zeroed() };
    feraiseexcept(FE_INVALID);
    assert_eq!(feholdexcept(&mut env), 0);
    // feholdexcept clears flags.
    assert_eq!(fetestexcept(FE_ALL_EXCEPT), 0);
    feraiseexcept(FE_INEXACT);
    // feupdateenv reinstates env then re-raises currently-held flags.
    assert_eq!(feupdateenv(&env), 0);
    assert_eq!(fetestexcept(FE_INEXACT), FE_INEXACT);
    feclearexcept(FE_ALL_EXCEPT);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn enable_disable_trap_bits() {
    fedisableexcept(FE_ALL_EXCEPT);
    assert_eq!(fegetexcept(), 0);
    feenableexcept(FE_DIVBYZERO);
    assert_eq!(fegetexcept() & FE_DIVBYZERO, FE_DIVBYZERO);
    // feenableexcept returns the previous enabled set.
    let prev = fedisableexcept(FE_DIVBYZERO);
    assert_eq!(prev & FE_DIVBYZERO, FE_DIVBYZERO);
    assert_eq!(fegetexcept() & FE_DIVBYZERO, 0);
    fedisableexcept(FE_ALL_EXCEPT);
}
