//! fenv — `<fenv.h>` floating-point environment (docs/59§6 G15).
//! Arch-specific: x86_64 drives the SSE MXCSR (exception flags bits 0-5,
//! masks bits 7-12, rounding bits 13-14) plus the legacy x87 control+status
//! word; aarch64 drives FPCR (rounding/masks) + FPSR (exception flags). The
//! C-ABI surface + dispatch lives here; the register read/write asm is the
//! per-arch backend (x86_64.rs / aarch64.rs). FE_* exception/rounding consts
//! + fenv_t/fexcept_t layout match host glibc bits/fenv.h per arch.
#![allow(non_camel_case_types)] // C ABI type names

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
use x86_64 as imp;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
use aarch64 as imp;

// Host-build fallback (dev box type-checks the rlib on non-target arches):
// no FP-env registers, so the backend is a no-op shim. Hosted differential
// tests hit the host glibc directly, never this path.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod host;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use host as imp;

// ---- FE_* exception bits (match bits/fenv.h per arch) ----
// x86: bit positions of the FPU control/status word. aarch64: FPSR cumulative
// exception bits. Both arches happen to share the 1/2/4/8/16 numbering for the
// five C99 exceptions (aarch64 FPSR IOC/DZC/OFC/UFC/IXC are bits 0-4; x86
// IE/DE/ZE/OE/UE/PE map FE_INVALID=IE, FE_DIVBYZERO=ZE, FE_OVERFLOW=OE,
// FE_UNDERFLOW=UE, FE_INEXACT=PE). The numeric values below are the FE_*
// macros each host <fenv.h> defines; the per-arch backend converts to/from the
// raw register bit layout.
#[cfg(target_arch = "x86_64")]
mod fe {
    pub const FE_INVALID: i32 = 0x01;
    pub const FE_DIVBYZERO: i32 = 0x04;
    pub const FE_OVERFLOW: i32 = 0x08;
    pub const FE_UNDERFLOW: i32 = 0x10;
    pub const FE_INEXACT: i32 = 0x20;
    pub const FE_TONEAREST: i32 = 0x000;
    pub const FE_DOWNWARD: i32 = 0x400;
    pub const FE_UPWARD: i32 = 0x800;
    pub const FE_TOWARDZERO: i32 = 0xc00;
}
#[cfg(not(target_arch = "x86_64"))]
mod fe {
    pub const FE_INVALID: i32 = 0x01;
    pub const FE_DIVBYZERO: i32 = 0x02;
    pub const FE_OVERFLOW: i32 = 0x04;
    pub const FE_UNDERFLOW: i32 = 0x08;
    pub const FE_INEXACT: i32 = 0x10;
    pub const FE_TONEAREST: i32 = 0x000000;
    pub const FE_UPWARD: i32 = 0x400000;
    pub const FE_DOWNWARD: i32 = 0x800000;
    pub const FE_TOWARDZERO: i32 = 0xc00000;
}
use fe::*;

const FE_ALL_EXCEPT: i32 = FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT;
const FE_ROUND_MASK: i32 = FE_TONEAREST | FE_DOWNWARD | FE_UPWARD | FE_TOWARDZERO;

/// `fexcept_t` — opaque exception-flag store. x86: `unsigned short`; aarch64:
/// `unsigned int`. Sized per arch to match host bits/fenv.h.
#[cfg(target_arch = "x86_64")]
pub type fexcept_t = u16;
#[cfg(not(target_arch = "x86_64"))]
pub type fexcept_t = u32;

pub use imp::{femode_t, fenv_t};

// ---- core operations (work fns; the C exports wrap these) ----

/// # C: int feclearexcept(int excepts)
pub(crate) fn feclearexcept(excepts: i32) -> i32 { imp::clearexcept(excepts & FE_ALL_EXCEPT); 0 }

/// # C: int fetestexcept(int excepts)
pub(crate) fn fetestexcept(excepts: i32) -> i32 { imp::testexcept() & excepts & FE_ALL_EXCEPT }

/// # C: int feraiseexcept(int excepts)
pub(crate) fn feraiseexcept(excepts: i32) -> i32 { imp::raiseexcept(excepts & FE_ALL_EXCEPT); 0 }

/// # C: int fesetexcept(int excepts) — set flags without trapping (C23/GNU)
pub(crate) fn fesetexcept(excepts: i32) -> i32 { imp::setexcept(excepts & FE_ALL_EXCEPT); 0 }

/// # C: int fegetexceptflag(fexcept_t *flagp, int excepts)
pub(crate) fn fegetexceptflag(flagp: &mut fexcept_t, excepts: i32) -> i32 {
    *flagp = (imp::testexcept() & excepts & FE_ALL_EXCEPT) as fexcept_t;
    0
}

/// # C: int fesetexceptflag(const fexcept_t *flagp, int excepts) — restore flags, no trap
pub(crate) fn fesetexceptflag(flagp: &fexcept_t, excepts: i32) -> i32 {
    let want = (*flagp as i32) & excepts & FE_ALL_EXCEPT;
    imp::clearexcept(excepts & FE_ALL_EXCEPT);
    imp::setexcept(want);
    0
}

/// # C: int fetestexceptflag(const fexcept_t *flagp, int excepts) — test stored flags (C23/GNU)
pub(crate) fn fetestexceptflag(flagp: &fexcept_t, excepts: i32) -> i32 {
    (*flagp as i32) & excepts & FE_ALL_EXCEPT
}

/// # C: int fegetround(void)
pub(crate) fn fegetround() -> i32 { imp::getround() & FE_ROUND_MASK }

/// # C: int fesetround(int rounding_mode)
pub(crate) fn fesetround(mode: i32) -> i32 {
    if mode & !FE_ROUND_MASK != 0 || (mode != FE_TONEAREST && mode != FE_DOWNWARD && mode != FE_UPWARD && mode != FE_TOWARDZERO) {
        return 1; // invalid mode → nonzero
    }
    imp::setround(mode);
    0
}

/// # C: int fegetenv(fenv_t *envp)
pub(crate) fn fegetenv(envp: &mut fenv_t) -> i32 { *envp = imp::getenv(); 0 }

/// # C: int fesetenv(const fenv_t *envp)
pub(crate) fn fesetenv(envp: &fenv_t) -> i32 { imp::setenv(envp); 0 }

/// # C: int feholdexcept(fenv_t *envp) — save env, clear flags, mask all
pub(crate) fn feholdexcept(envp: &mut fenv_t) -> i32 {
    *envp = imp::getenv();
    imp::clearexcept(FE_ALL_EXCEPT);
    imp::disableexcept(FE_ALL_EXCEPT);
    0
}

/// # C: int feupdateenv(const fenv_t *envp) — install env, then re-raise held flags
pub(crate) fn feupdateenv(envp: &fenv_t) -> i32 {
    let held = imp::testexcept() & FE_ALL_EXCEPT;
    imp::setenv(envp);
    imp::raiseexcept(held);
    0
}

// ---- GNU trap-enable extensions ----

/// # C: int feenableexcept(int excepts) — returns previous enabled set
pub(crate) fn feenableexcept(excepts: i32) -> i32 {
    let prev = imp::getexcept();
    imp::enableexcept(excepts & FE_ALL_EXCEPT);
    prev
}

/// # C: int fedisableexcept(int excepts) — returns previous enabled set
pub(crate) fn fedisableexcept(excepts: i32) -> i32 {
    let prev = imp::getexcept();
    imp::disableexcept(excepts & FE_ALL_EXCEPT);
    prev
}

/// # C: int fegetexcept(void) — currently-trapping exceptions
pub(crate) fn fegetexcept() -> i32 { imp::getexcept() }

// ---- C23/GNU control-mode (femode_t) ----

/// # C: int fegetmode(femode_t *modep)
pub(crate) fn fegetmode(modep: &mut femode_t) -> i32 { *modep = imp::getmode(); 0 }

/// # C: int fesetmode(const femode_t *modep)
pub(crate) fn fesetmode(modep: &femode_t) -> i32 { imp::setmode(modep); 0 }

// ---- C-ABI exports (shipped libc only) ----
#[cfg(feature = "freestanding")]
mod exports {
    use super::{femode_t, fenv_t, fexcept_t};

    /// # C: int feclearexcept(int)
    #[no_mangle]
    pub extern "C" fn feclearexcept(excepts: i32) -> i32 { super::feclearexcept(excepts) }
    /// # C: int fetestexcept(int)
    #[no_mangle]
    pub extern "C" fn fetestexcept(excepts: i32) -> i32 { super::fetestexcept(excepts) }
    /// # C: int feraiseexcept(int)
    #[no_mangle]
    pub extern "C" fn feraiseexcept(excepts: i32) -> i32 { super::feraiseexcept(excepts) }
    /// # C: int fesetexcept(int)
    #[no_mangle]
    pub extern "C" fn fesetexcept(excepts: i32) -> i32 { super::fesetexcept(excepts) }
    /// # C: int fegetexceptflag(fexcept_t*, int)
    #[no_mangle]
    pub unsafe extern "C" fn fegetexceptflag(flagp: *mut fexcept_t, excepts: i32) -> i32 {
        // SAFETY: C caller passes a valid writable fexcept_t per <fenv.h>; we
        // write exactly one fexcept_t. Null is a caller contract violation.
        super::fegetexceptflag(unsafe { &mut *flagp }, excepts)
    }
    /// # C: int fesetexceptflag(const fexcept_t*, int)
    #[no_mangle]
    pub unsafe extern "C" fn fesetexceptflag(flagp: *const fexcept_t, excepts: i32) -> i32 {
        // SAFETY: C caller passes a valid readable fexcept_t per <fenv.h>; we
        // read exactly one fexcept_t. Null is a caller contract violation.
        super::fesetexceptflag(unsafe { &*flagp }, excepts)
    }
    /// # C: int fetestexceptflag(const fexcept_t*, int)
    #[no_mangle]
    pub unsafe extern "C" fn fetestexceptflag(flagp: *const fexcept_t, excepts: i32) -> i32 {
        // SAFETY: C caller passes a valid readable fexcept_t per <fenv.h>; we
        // read exactly one fexcept_t. Null is a caller contract violation.
        super::fetestexceptflag(unsafe { &*flagp }, excepts)
    }
    /// # C: int fegetround(void)
    #[no_mangle]
    pub extern "C" fn fegetround() -> i32 { super::fegetround() }
    /// # C: int fesetround(int)
    #[no_mangle]
    pub extern "C" fn fesetround(mode: i32) -> i32 { super::fesetround(mode) }
    /// # C: int fegetenv(fenv_t*)
    #[no_mangle]
    pub unsafe extern "C" fn fegetenv(envp: *mut fenv_t) -> i32 {
        // SAFETY: C caller passes a valid writable fenv_t per <fenv.h>; we
        // write exactly one fenv_t. Null is a caller contract violation.
        super::fegetenv(unsafe { &mut *envp })
    }
    /// # C: int fesetenv(const fenv_t*)
    #[no_mangle]
    pub unsafe extern "C" fn fesetenv(envp: *const fenv_t) -> i32 {
        // FE_DFL_ENV is (const fenv_t*)-1; install the default environment.
        if envp as isize == -1 { return super::imp::set_default_env(); }
        // SAFETY: C caller passes a valid readable fenv_t per <fenv.h> (or the
        // FE_DFL_ENV sentinel handled above); we read exactly one fenv_t.
        super::fesetenv(unsafe { &*envp })
    }
    /// # C: int feholdexcept(fenv_t*)
    #[no_mangle]
    pub unsafe extern "C" fn feholdexcept(envp: *mut fenv_t) -> i32 {
        // SAFETY: C caller passes a valid writable fenv_t per <fenv.h>; we
        // write exactly one fenv_t. Null is a caller contract violation.
        super::feholdexcept(unsafe { &mut *envp })
    }
    /// # C: int feupdateenv(const fenv_t*)
    #[no_mangle]
    pub unsafe extern "C" fn feupdateenv(envp: *const fenv_t) -> i32 {
        if envp as isize == -1 {
            let held = super::imp::testexcept() & super::FE_ALL_EXCEPT;
            super::imp::set_default_env();
            super::imp::raiseexcept(held);
            return 0;
        }
        // SAFETY: C caller passes a valid readable fenv_t per <fenv.h> (or the
        // FE_DFL_ENV sentinel handled above); we read exactly one fenv_t.
        super::feupdateenv(unsafe { &*envp })
    }
    /// # C: int feenableexcept(int)
    #[no_mangle]
    pub extern "C" fn feenableexcept(excepts: i32) -> i32 { super::feenableexcept(excepts) }
    /// # C: int fedisableexcept(int)
    #[no_mangle]
    pub extern "C" fn fedisableexcept(excepts: i32) -> i32 { super::fedisableexcept(excepts) }
    /// # C: int fegetexcept(void)
    #[no_mangle]
    pub extern "C" fn fegetexcept() -> i32 { super::fegetexcept() }
    /// # C: int fegetmode(femode_t*)
    #[no_mangle]
    pub unsafe extern "C" fn fegetmode(modep: *mut femode_t) -> i32 {
        // SAFETY: C caller passes a valid writable femode_t per <fenv.h>; we
        // write exactly one femode_t. Null is a caller contract violation.
        super::fegetmode(unsafe { &mut *modep })
    }
    /// # C: int fesetmode(const femode_t*)
    #[no_mangle]
    pub unsafe extern "C" fn fesetmode(modep: *const femode_t) -> i32 {
        // FE_DFL_MODE is (const femode_t*)-1; install the default modes.
        if modep as isize == -1 { return super::imp::set_default_mode(); }
        // SAFETY: C caller passes a valid readable femode_t per <fenv.h> (or
        // the FE_DFL_MODE sentinel handled above); we read one femode_t.
        super::fesetmode(unsafe { &*modep })
    }
}

#[cfg(test)]
mod tests;
