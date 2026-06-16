// C23 *pi trig + *m1/*p1 (docs/59§6 §9.1). sinpi/cospi/tanpi reduce the argument
// to [-0.5,0.5] times an integer so the result is EXACT at integer/half-integer
// (sinpi(n)=±0, sinpi(n+0.5)=±1, cospi(n+0.5)=0). asinpi/acospi/atanpi/atan2pi
// are the inverse fns scaled by 1/pi. expN m1 = expN(x)-1; logN p1 = logN(1+x).
#![cfg(feature = "freestanding")]
use super::atrig::{acos, asin, atan, atan2};
use super::basic::round;
use super::exp::exp;
use super::hyper::exp2;
use super::log::{log10, log2};
use super::trig::{cos, sin};

const PI: f64 = core::f64::consts::PI;

fn k_sinpi(x: f64) -> f64 {
    if x.is_nan() { return x; }
    if x.is_infinite() { return f64::NAN; }
    let i = round(x);
    let f = x - i;
    if f == 0.0 { return if x.is_sign_negative() { -0.0 } else { 0.0 }; }
    let s = if f == 0.5 { 1.0 } else if f == -0.5 { -1.0 } else { sin(PI * f) };
    if (i as i64) & 1 == 0 { s } else { -s }
}
fn k_cospi(x: f64) -> f64 {
    if x.is_nan() { return x; }
    if x.is_infinite() { return f64::NAN; }
    let i = round(x);
    let f = x - i;
    let c = if f == 0.5 || f == -0.5 { 0.0 } else if f == 0.0 { 1.0 } else { cos(PI * f) };
    if (i as i64) & 1 == 0 { c } else { -c }
}
fn k_tanpi(x: f64) -> f64 {
    if x.is_nan() { return x; }
    if x.is_infinite() { return f64::NAN; }
    let s = k_sinpi(x); let c = k_cospi(x);
    if c == 0.0 { return if s.is_sign_negative() { f64::NEG_INFINITY } else { f64::INFINITY }; }
    s / c
}
fn k_asinpi(x: f64) -> f64 { asin(x) / PI }
fn k_acospi(x: f64) -> f64 { acos(x) / PI }
fn k_atanpi(x: f64) -> f64 { atan(x) / PI }
fn k_exp10m1(x: f64) -> f64 { exp(x * core::f64::consts::LN_10) - 1.0 }
fn k_exp2m1(x: f64) -> f64 { exp2(x) - 1.0 }
fn k_log10p1(x: f64) -> f64 { log10(1.0 + x) }
fn k_log2p1(x: f64) -> f64 { log2(1.0 + x) }

macro_rules! u1 { ($n64:ident, $n32:ident, $core:ident) => {
    // # C: double <n64>(double) / float <n32>(float)
    #[no_mangle] pub extern "C" fn $n64(x: f64) -> f64 { $core(x) }
    #[no_mangle] pub extern "C" fn $n32(x: f32) -> f32 { $core(x as f64) as f32 }
}; }
u1!(sinpi, sinpif, k_sinpi);
u1!(cospi, cospif, k_cospi);
u1!(tanpi, tanpif, k_tanpi);
u1!(asinpi, asinpif, k_asinpi);
u1!(acospi, acospif, k_acospi);
u1!(atanpi, atanpif, k_atanpi);
u1!(exp10m1, exp10m1f, k_exp10m1);
u1!(exp2m1, exp2m1f, k_exp2m1);
u1!(log10p1, log10p1f, k_log10p1);
u1!(log2p1, log2p1f, k_log2p1);
// # C: double atan2pi(double, double) / float atan2pif(float, float)
#[no_mangle] pub extern "C" fn atan2pi(y: f64, x: f64) -> f64 { atan2(y, x) / PI }
#[no_mangle] pub extern "C" fn atan2pif(y: f32, x: f32) -> f32 { (atan2(y as f64, x as f64) / PI) as f32 }
