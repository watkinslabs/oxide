// glibc finite libm compatibility entry points. Modern headers do not call
// these directly, but old binaries may bind them by symbol.

use super::{atrig, basic, exp, extra, extras, hyper, log, pow, special, sqrt};

macro_rules! f64_1 {
    ($name:ident, $path:path) => {
        #[no_mangle]
        pub extern "C" fn $name(x: f64) -> f64 {
            $path(x)
        }
    };
}

macro_rules! f32_1 {
    ($name:ident, $path:path) => {
        #[no_mangle]
        pub extern "C" fn $name(x: f32) -> f32 {
            $path(x)
        }
    };
}

macro_rules! f64_2 {
    ($name:ident, $path:path) => {
        #[no_mangle]
        pub extern "C" fn $name(x: f64, y: f64) -> f64 {
            $path(x, y)
        }
    };
}

macro_rules! f32_2 {
    ($name:ident, $path:path) => {
        #[no_mangle]
        pub extern "C" fn $name(x: f32, y: f32) -> f32 {
            $path(x, y)
        }
    };
}

f64_1!(__acos_finite, atrig::acos);
f32_1!(__acosf_finite, atrig::acosf);
f64_1!(__acosh_finite, extra::acosh);
f32_1!(__acoshf_finite, extra::acoshf);
f64_1!(__asin_finite, atrig::asin);
f32_1!(__asinf_finite, atrig::asinf);
f64_2!(__atan2_finite, atrig::atan2);
f32_2!(__atan2f_finite, atrig::atan2f);
f64_1!(__atanh_finite, extra::atanh);
f32_1!(__atanhf_finite, extra::atanhf);
f64_1!(__cosh_finite, hyper::cosh);
f32_1!(__coshf_finite, hyper::coshf);
f64_1!(__exp10_finite, extras::exp10);
f32_1!(__exp10f_finite, extras::exp10f);
f64_1!(__exp2_finite, hyper::exp2);
f32_1!(__exp2f_finite, hyper::exp2f);
f64_1!(__exp_finite, exp::exp);
f32_1!(__expf_finite, exp::expf);
f64_2!(__fmod_finite, basic::fmod);
#[no_mangle]
pub extern "C" fn __fmodf_finite(x: f32, y: f32) -> f32 {
    basic::fmod(x as f64, y as f64) as f32
}
f64_2!(__hypot_finite, extra::hypot);
f32_2!(__hypotf_finite, extra::hypotf);
f64_1!(__j0_finite, special::j0);
#[no_mangle]
pub extern "C" fn __j0f_finite(x: f32) -> f32 {
    special::j0(x as f64) as f32
}
f64_1!(__j1_finite, special::j1);
#[no_mangle]
pub extern "C" fn __j1f_finite(x: f32) -> f32 {
    special::j1(x as f64) as f32
}
f64_1!(__log10_finite, log::log10);
f32_1!(__log10f_finite, log::log10f);
f64_1!(__log2_finite, log::log2);
f32_1!(__log2f_finite, log::log2f);
f64_1!(__log_finite, log::log);
f32_1!(__logf_finite, log::logf);
f64_2!(__pow_finite, pow::pow);
f32_2!(__powf_finite, pow::powf);
f64_2!(__remainder_finite, basic::remainder);
#[no_mangle]
pub extern "C" fn __remainderf_finite(x: f32, y: f32) -> f32 {
    basic::remainder(x as f64, y as f64) as f32
}
f64_2!(__scalb_finite, extras::scalb);

#[no_mangle]
pub extern "C" fn __scalbf_finite(x: f32, n: f32) -> f32 {
    extras::scalb(x as f64, n as f64) as f32
}

f64_1!(__sinh_finite, hyper::sinh);
f32_1!(__sinhf_finite, hyper::sinhf);
f64_1!(__sqrt_finite, sqrt::sqrt);
f32_1!(__sqrtf_finite, sqrt::sqrtf);
f64_1!(__y0_finite, special::y0);
#[no_mangle]
pub extern "C" fn __y0f_finite(x: f32) -> f32 {
    special::y0(x as f64) as f32
}
f64_1!(__y1_finite, special::y1);
#[no_mangle]
pub extern "C" fn __y1f_finite(x: f32) -> f32 {
    special::y1(x as f64) as f32
}

#[no_mangle]
pub extern "C" fn __jn_finite(n: i32, x: f64) -> f64 {
    special::jn(n, x)
}

#[no_mangle]
pub extern "C" fn __jnf_finite(n: i32, x: f32) -> f32 {
    special::jn(n, x as f64) as f32
}

#[no_mangle]
pub extern "C" fn __yn_finite(n: i32, x: f64) -> f64 {
    special::yn(n, x)
}

#[no_mangle]
pub extern "C" fn __ynf_finite(n: i32, x: f32) -> f32 {
    special::yn(n, x as f64) as f32
}

#[no_mangle]
pub unsafe extern "C" fn __gamma_r_finite(x: f64, signp: *mut i32) -> f64 {
    // SAFETY: signp is the writable sign out-param required by gamma_r.
    unsafe { special::lgamma_r(x, &mut *signp) }
}

#[no_mangle]
pub unsafe extern "C" fn __gammaf_r_finite(x: f32, signp: *mut i32) -> f32 {
    // SAFETY: signp is the writable sign out-param required by gammaf_r.
    unsafe { special::lgamma_r(x as f64, &mut *signp) as f32 }
}

#[no_mangle]
pub unsafe extern "C" fn __lgamma_r_finite(x: f64, signp: *mut i32) -> f64 {
    // SAFETY: signp is the writable sign out-param required by lgamma_r.
    unsafe { special::lgamma_r(x, &mut *signp) }
}

#[no_mangle]
pub unsafe extern "C" fn __lgammaf_r_finite(x: f32, signp: *mut i32) -> f32 {
    // SAFETY: signp is the writable sign out-param required by lgammaf_r.
    unsafe { special::lgamma_r(x as f64, &mut *signp) as f32 }
}
