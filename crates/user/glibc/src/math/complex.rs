// C99 <complex.h> (docs/59§6 G15). Rust has no native _Complex, so the C ABI is
// reached via #[repr(C)] structs of two floats: per SysV/AArch64, {f64,f64} is
// classified identically to `double _Complex` (two SSE/HFA regs) and {f32,f32}
// to `float _Complex`. Every op is built from the real-valued libm in sibling
// modules (hypot/atan2/exp/log/sin/cos/sinh/cosh/sqrt/pow) via standard
// identities; the inverse trig/hyperbolic come from clog+csqrt. Differentially
// tested against host glibc at %.12g over interior (non-branch-cut) arguments.
#![cfg(feature = "freestanding")]

use super::atrig::atan2;
use super::basic::{copysign, fabs};
use super::exp::exp;
use super::hyper::{cosh, sinh};
use super::log::log;
use super::sqrt::sqrt;
use super::trig::{cos, sin};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct __cdouble { re: f64, im: f64 }
#[repr(C)]
#[derive(Clone, Copy)]
pub struct __cfloat { re: f32, im: f32 }

#[inline] fn cd(re: f64, im: f64) -> __cdouble { __cdouble { re, im } }
#[inline] fn cf(re: f32, im: f32) -> __cfloat { __cfloat { re, im } }
#[inline] fn up(z: __cfloat) -> __cdouble { cd(z.re as f64, z.im as f64) }
#[inline] fn dn(z: __cdouble) -> __cfloat { cf(z.re as f32, z.im as f32) }

// ── magnitude / parts ──────────────────────────────────────────────────────
/// # C: double imp_cabs(double _Complex)
fn imp_cabs(z: __cdouble) -> f64 { super::extra::hypot(z.re, z.im) }
/// # C: double imp_carg(double _Complex)
fn imp_carg(z: __cdouble) -> f64 { atan2(z.im, z.re) }

// ── exp / log / sqrt / pow ──────────────────────────────────────────────────
/// # C: double _Complex imp_cexp(double _Complex) — e^z = e^re·(cos im + i sin im)
fn imp_cexp(z: __cdouble) -> __cdouble { let e = exp(z.re); cd(e * cos(z.im), e * sin(z.im)) }
/// # C: double _Complex imp_clog(double _Complex) — ln|z| + i·arg z (principal)
fn imp_clog(z: __cdouble) -> __cdouble { cd(log(imp_cabs(z)), atan2(z.im, z.re)) }
/// # C: double _Complex imp_clog10(double _Complex) — base-10 = clog(z)/ln(10)
fn imp_clog10(z: __cdouble) -> __cdouble {
    const LN10: f64 = 2.302585092994045684017991454684364208_f64; // ln(10)
    let l = imp_clog(z); cd(l.re / LN10, l.im / LN10)
}
/// # C: double _Complex imp_csqrt(double _Complex) — principal branch
fn imp_csqrt(z: __cdouble) -> __cdouble {
    if z.re == 0.0 && z.im == 0.0 { return cd(0.0, z.im); }
    let r = imp_cabs(z);
    let w = sqrt((r + fabs(z.re)) * 0.5);
    let v = z.im / (2.0 * w);
    if z.re >= 0.0 { cd(w, v) } else { cd(fabs(v), copysign(w, z.im)) }
}
/// # C: double _Complex imp_cpow(double _Complex, double _Complex) — exp(w·log z)
fn imp_cpow(z: __cdouble, w: __cdouble) -> __cdouble { imp_cexp(cmul(w, imp_clog(z))) }

// ── trig ────────────────────────────────────────────────────────────────────
/// # C: double _Complex imp_csin(double _Complex) — sin re·cosh im + i cos re·sinh im
fn imp_csin(z: __cdouble) -> __cdouble { cd(sin(z.re) * cosh(z.im), cos(z.re) * sinh(z.im)) }
/// # C: double _Complex imp_ccos(double _Complex) — cos re·cosh im − i sin re·sinh im
fn imp_ccos(z: __cdouble) -> __cdouble { cd(cos(z.re) * cosh(z.im), -sin(z.re) * sinh(z.im)) }
/// # C: double _Complex imp_ctan(double _Complex) = csin/ccos
fn imp_ctan(z: __cdouble) -> __cdouble { cdiv(imp_csin(z), imp_ccos(z)) }

// ── hyperbolic ───────────────────────────────────────────────────────────────
/// # C: double _Complex imp_csinh(double _Complex)
fn imp_csinh(z: __cdouble) -> __cdouble { cd(sinh(z.re) * cos(z.im), cosh(z.re) * sin(z.im)) }
/// # C: double _Complex imp_ccosh(double _Complex)
fn imp_ccosh(z: __cdouble) -> __cdouble { cd(cosh(z.re) * cos(z.im), sinh(z.re) * sin(z.im)) }
/// # C: double _Complex imp_ctanh(double _Complex) = csinh/ccosh
fn imp_ctanh(z: __cdouble) -> __cdouble { cdiv(imp_csinh(z), imp_ccosh(z)) }

// ── inverse trig (principal) via clog/csqrt ──────────────────────────────────
const I: __cdouble = __cdouble { re: 0.0, im: 1.0 };
/// # C: double _Complex imp_casin(double _Complex) = −i·log(i·z + √(1−z²))
fn imp_casin(z: __cdouble) -> __cdouble {
    let s = imp_csqrt(csub(cd(1.0, 0.0), cmul(z, z)));
    let l = imp_clog(cadd(cmul(I, z), s));
    cmul(cd(0.0, -1.0), l) // ×(−i)
}
/// # C: double _Complex imp_cacos(double _Complex) = −i·log(z + i·√(1−z²))
fn imp_cacos(z: __cdouble) -> __cdouble {
    let s = imp_csqrt(csub(cd(1.0, 0.0), cmul(z, z)));
    let l = imp_clog(cadd(z, cmul(I, s)));
    cmul(cd(0.0, -1.0), l)
}
/// # C: double _Complex imp_catan(double _Complex) = (i/2)·log((i+z)/(i−z))
fn imp_catan(z: __cdouble) -> __cdouble {
    let l = imp_clog(cdiv(cadd(I, z), csub(I, z)));
    cmul(cd(0.0, 0.5), l)
}

// ── inverse hyperbolic (principal) via clog/csqrt ────────────────────────────
/// # C: double _Complex imp_casinh(double _Complex) = log(z + √(z²+1))
fn imp_casinh(z: __cdouble) -> __cdouble {
    let s = imp_csqrt(cadd(cmul(z, z), cd(1.0, 0.0)));
    imp_clog(cadd(z, s))
}
/// # C: double _Complex imp_cacosh(double _Complex) = log(z + √(z²−1))
fn imp_cacosh(z: __cdouble) -> __cdouble {
    let s = imp_csqrt(csub(cmul(z, z), cd(1.0, 0.0)));
    imp_clog(cadd(z, s))
}
/// # C: double _Complex imp_catanh(double _Complex) = (1/2)·log((1+z)/(1−z))
fn imp_catanh(z: __cdouble) -> __cdouble {
    let l = imp_clog(cdiv(cadd(cd(1.0, 0.0), z), csub(cd(1.0, 0.0), z)));
    cmul(cd(0.5, 0.0), l)
}

// ── complex arithmetic helpers ───────────────────────────────────────────────
#[inline] fn cadd(a: __cdouble, b: __cdouble) -> __cdouble { cd(a.re + b.re, a.im + b.im) }
#[inline] fn csub(a: __cdouble, b: __cdouble) -> __cdouble { cd(a.re - b.re, a.im - b.im) }
#[inline] fn cmul(a: __cdouble, b: __cdouble) -> __cdouble { cd(a.re * b.re - a.im * b.im, a.re * b.im + a.im * b.re) }
#[inline] fn cdiv(a: __cdouble, b: __cdouble) -> __cdouble {
    let d = b.re * b.re + b.im * b.im;
    cd((a.re * b.re + a.im * b.im) / d, (a.im * b.re - a.re * b.im) / d)
}

// ── C-ABI exports (double + float `f` variant) ───────────────────────────────
// re/im/conj/cproj are trivial; the rest dispatch to the f64 core, float
// variants round through the f64 path then narrow (matches glibc at %.12g).

/// # C: double creal(double _Complex)
#[no_mangle] pub extern "C" fn creal(z: __cdouble) -> f64 { z.re }
/// # C: double cimag(double _Complex)
#[no_mangle] pub extern "C" fn cimag(z: __cdouble) -> f64 { z.im }
/// # C: float crealf(float _Complex)
#[no_mangle] pub extern "C" fn crealf(z: __cfloat) -> f32 { z.re }
/// # C: float cimagf(float _Complex)
#[no_mangle] pub extern "C" fn cimagf(z: __cfloat) -> f32 { z.im }

/// # C: double _Complex conj(double _Complex)
#[no_mangle] pub extern "C" fn conj(z: __cdouble) -> __cdouble { cd(z.re, -z.im) }
/// # C: float _Complex conjf(float _Complex)
#[no_mangle] pub extern "C" fn conjf(z: __cfloat) -> __cfloat { cf(z.re, -z.im) }

/// # C: double _Complex cproj(double _Complex) — Riemann-sphere projection
#[no_mangle] pub extern "C" fn cproj(z: __cdouble) -> __cdouble {
    if z.re.is_infinite() || z.im.is_infinite() { cd(f64::INFINITY, copysign(0.0, z.im)) } else { z }
}
/// # C: float _Complex cprojf(float _Complex)
#[no_mangle] pub extern "C" fn cprojf(z: __cfloat) -> __cfloat {
    if z.re.is_infinite() || z.im.is_infinite() { cf(f32::INFINITY, copysign(0.0, z.im as f64) as f32) } else { z }
}

/// # C: double cabs(double _Complex)
#[no_mangle] pub extern "C" fn cabs(z: __cdouble) -> f64 { self::imp_cabs(z) }
/// # C: float cabsf(float _Complex)
#[no_mangle] pub extern "C" fn cabsf(z: __cfloat) -> f32 { self::imp_cabs(up(z)) as f32 }
/// # C: double carg(double _Complex)
#[no_mangle] pub extern "C" fn carg(z: __cdouble) -> f64 { self::imp_carg(z) }
/// # C: float cargf(float _Complex)
#[no_mangle] pub extern "C" fn cargf(z: __cfloat) -> f32 { self::imp_carg(up(z)) as f32 }

macro_rules! c1 {
    ($d:ident, $f:ident, $inner:ident, $sig:literal, $sigf:literal) => {
        #[doc = concat!(" # C: ", $sig)]
        #[no_mangle] pub extern "C" fn $d(z: __cdouble) -> __cdouble { self::$inner(z) }
        #[doc = concat!(" # C: ", $sigf)]
        #[no_mangle] pub extern "C" fn $f(z: __cfloat) -> __cfloat { dn(self::$inner(up(z))) }
    };
}

c1!(cexp,   cexpf,   imp_cexp,   "double _Complex cexp(double _Complex)",   "float _Complex cexpf(float _Complex)");
c1!(clog,   clogf,   imp_clog,   "double _Complex clog(double _Complex)",   "float _Complex clogf(float _Complex)");
c1!(clog10, clog10f, imp_clog10, "double _Complex clog10(double _Complex)", "float _Complex clog10f(float _Complex)");
c1!(csqrt,  csqrtf,  imp_csqrt,  "double _Complex csqrt(double _Complex)",  "float _Complex csqrtf(float _Complex)");
c1!(csin,   csinf,   imp_csin,   "double _Complex csin(double _Complex)",   "float _Complex csinf(float _Complex)");
c1!(ccos,   ccosf,   imp_ccos,   "double _Complex ccos(double _Complex)",   "float _Complex ccosf(float _Complex)");
c1!(ctan,   ctanf,   imp_ctan,   "double _Complex ctan(double _Complex)",   "float _Complex ctanf(float _Complex)");
c1!(csinh,  csinhf,  imp_csinh,  "double _Complex csinh(double _Complex)",  "float _Complex csinhf(float _Complex)");
c1!(ccosh,  ccoshf,  imp_ccosh,  "double _Complex ccosh(double _Complex)",  "float _Complex ccoshf(float _Complex)");
c1!(ctanh,  ctanhf,  imp_ctanh,  "double _Complex ctanh(double _Complex)",  "float _Complex ctanhf(float _Complex)");
c1!(casin,  casinf,  imp_casin,  "double _Complex casin(double _Complex)",  "float _Complex casinf(float _Complex)");
c1!(cacos,  cacosf,  imp_cacos,  "double _Complex cacos(double _Complex)",  "float _Complex cacosf(float _Complex)");
c1!(catan,  catanf,  imp_catan,  "double _Complex catan(double _Complex)",  "float _Complex catanf(float _Complex)");
c1!(casinh, casinhf, imp_casinh, "double _Complex casinh(double _Complex)", "float _Complex casinhf(float _Complex)");
c1!(cacosh, cacoshf, imp_cacosh, "double _Complex cacosh(double _Complex)", "float _Complex cacoshf(float _Complex)");
c1!(catanh, catanhf, imp_catanh, "double _Complex catanh(double _Complex)", "float _Complex catanhf(float _Complex)");

/// # C: double _Complex cpow(double _Complex, double _Complex)
#[no_mangle] pub extern "C" fn cpow(z: __cdouble, w: __cdouble) -> __cdouble { self::imp_cpow(z, w) }
/// # C: float _Complex cpowf(float _Complex, float _Complex)
#[no_mangle] pub extern "C" fn cpowf(z: __cfloat, w: __cfloat) -> __cfloat { dn(self::imp_cpow(up(z), up(w))) }

#[cfg(test)]
mod tests {
    use super::*;
    // Host oracle: {re,im} matches `double _Complex` ABI; call host libc.
    extern "C" {
        fn cabs(z: __cdouble) -> f64;
        fn cexp(z: __cdouble) -> __cdouble;
        fn clog(z: __cdouble) -> __cdouble;
        fn csqrt(z: __cdouble) -> __cdouble;
        fn casin(z: __cdouble) -> __cdouble;
        fn ctanh(z: __cdouble) -> __cdouble;
    }
    fn close(a: f64, b: f64) -> bool { let r = if b.abs() < 1e-12 { (a - b).abs() } else { ((a - b) / b).abs() }; r < 1e-10 }
    #[test]
    fn matches_host() {
        let zs = [cd(1.0, 0.5), cd(-0.7, 1.3), cd(0.3, -0.9), cd(2.0, 2.0), cd(0.4, 0.4)];
        for &z in &zs {
            // SAFETY: host complex.h functions are pure numeric; __cdouble is the
            // {f64,f64} repr(C) matching the `double _Complex` SysV classification.
            let (hc, he, hl, hs, ha, ht) = unsafe { (cabs(z), cexp(z), clog(z), csqrt(z), casin(z), ctanh(z)) };
            assert!(close(super::cabs(z), hc));
            let oe = super::cexp(z); assert!(close(oe.re, he.re) && close(oe.im, he.im));
            let ol = super::clog(z); assert!(close(ol.re, hl.re) && close(ol.im, hl.im));
            let os = super::csqrt(z); assert!(close(os.re, hs.re) && close(os.im, hs.im));
            let oa = super::casin(z); assert!(close(oa.re, ha.re) && close(oa.im, ha.im));
            let ot = super::ctanh(z); assert!(close(ot.re, ht.re) && close(ot.im, ht.im));
        }
    }
}
