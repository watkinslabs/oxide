// C23 fmaximum/fminimum family (docs/59§6 §9.1). Unlike fmax/fmin these
// PROPAGATE NaN and order -0.0 < +0.0. `_num` variants ignore a NaN operand
// (fmax/fmin-like) but keep the -0/+0 ordering. `_mag` compares by magnitude,
// falling back to the value compare on a tie. Pure; f32 wrappers via the f64
// core (exact for min/max selection).
#![cfg(feature = "freestanding")]
use super::basic as b;

// -0.0 < +0.0 tie-breaker: for equal/zero operands return the chosen sign.
fn pick_max(x: f64, y: f64) -> f64 { if b::signbit(x) { y } else { x } }
fn pick_min(x: f64, y: f64) -> f64 { if b::signbit(x) { x } else { y } }

fn k_fmaximum(x: f64, y: f64) -> f64 {
    if b::isnan(x) { return x; }
    if b::isnan(y) { return y; }
    if x > y { x } else if y > x { y } else { pick_max(x, y) }
}
fn k_fminimum(x: f64, y: f64) -> f64 {
    if b::isnan(x) { return x; }
    if b::isnan(y) { return y; }
    if x < y { x } else if y < x { y } else { pick_min(x, y) }
}
fn k_fmaximum_num(x: f64, y: f64) -> f64 {
    if b::isnan(x) { return y; }
    if b::isnan(y) { return x; }
    if x > y { x } else if y > x { y } else { pick_max(x, y) }
}
fn k_fminimum_num(x: f64, y: f64) -> f64 {
    if b::isnan(x) { return y; }
    if b::isnan(y) { return x; }
    if x < y { x } else if y < x { y } else { pick_min(x, y) }
}
fn k_fmaximum_mag(x: f64, y: f64) -> f64 {
    let (ax, ay) = (b::fabs(x), b::fabs(y));
    if ax > ay { x } else if ay > ax { y } else { k_fmaximum(x, y) }
}
fn k_fminimum_mag(x: f64, y: f64) -> f64 {
    let (ax, ay) = (b::fabs(x), b::fabs(y));
    if ax < ay { x } else if ay < ax { y } else { k_fminimum(x, y) }
}
fn k_fmaximum_mag_num(x: f64, y: f64) -> f64 {
    if b::isnan(x) { return y; }
    if b::isnan(y) { return x; }
    k_fmaximum_mag(x, y)
}
fn k_fminimum_mag_num(x: f64, y: f64) -> f64 {
    if b::isnan(x) { return y; }
    if b::isnan(y) { return x; }
    k_fminimum_mag(x, y)
}

macro_rules! exp2 {
    ($f64name:ident, $f32name:ident, $core:ident) => {
        // # C: double <f64name>(double, double)
        #[no_mangle] pub extern "C" fn $f64name(x: f64, y: f64) -> f64 { $core(x, y) }
        // # C: float <f32name>(float, float)
        #[no_mangle] pub extern "C" fn $f32name(x: f32, y: f32) -> f32 { $core(x as f64, y as f64) as f32 }
    };
}
exp2!(fmaximum, fmaximumf, k_fmaximum);
exp2!(fminimum, fminimumf, k_fminimum);
exp2!(fmaximum_num, fmaximum_numf, k_fmaximum_num);
exp2!(fminimum_num, fminimum_numf, k_fminimum_num);
exp2!(fmaximum_mag, fmaximum_magf, k_fmaximum_mag);
exp2!(fminimum_mag, fminimum_magf, k_fminimum_mag);
exp2!(fmaximum_mag_num, fmaximum_mag_numf, k_fmaximum_mag_num);
exp2!(fminimum_mag_num, fminimum_mag_numf, k_fminimum_mag_num);
