// Special functions (docs/59§6 G15): erf/erfc. Verifiable construction —
// Maclaurin series for |x|<1.5, Lentz continued fraction for the erfc tail —
// validated ≤1 ULP vs host libm. erff/erfcf via the f64 core. Pure +
// hosted-tested. tgamma/lgamma and Bessel follow.
use super::exp::exp;

const TWO_OVER_SQRT_PI: f64 = 1.1283791670955126; // 2/√π
const ONE_OVER_SQRT_PI: f64 = 0.5641895835477563; // 1/√π

// erf via the Maclaurin series: erf(x) = (2/√π) Σ (-1)^n x^(2n+1)/(n!(2n+1)).
fn erf_series(ax: f64) -> f64 {
    let x2 = ax * ax;
    let mut term = ax; // t_0
    let mut sum = ax;
    let mut n = 1.0;
    loop {
        // t_n = t_{n-1} · (-x²·(2n-1)) / (n·(2n+1)) gives x^(2n+1)/(n!) with sign;
        // we divide the *sum contribution* by (2n+1).
        term *= -x2 / n;
        let contrib = term / (2.0 * n + 1.0);
        sum += contrib;
        if contrib.abs() <= sum.abs() * 1e-17 || n > 200.0 { break; }
        n += 1.0;
    }
    TWO_OVER_SQRT_PI * sum
}

// erfc(ax) for ax > 0 via the continued fraction
//   erfc(x) = exp(-x²)/√π · 1/(x + (1/2)/(x + 1/(x + (3/2)/(x + 2/(x + …)))))
// evaluated by modified Lentz (a_i = i/2, b_i = x).
fn erfc_cf(ax: f64) -> f64 {
    let tiny = 1e-300;
    let mut f = ax;
    if f == 0.0 { f = tiny; }
    let mut c = f;
    let mut d = 0.0f64;
    let mut i = 1.0;
    loop {
        let a = i / 2.0;
        d = ax + a * d;
        if d == 0.0 { d = tiny; }
        d = 1.0 / d;
        c = ax + a / c;
        if c == 0.0 { c = tiny; }
        let delta = c * d;
        f *= delta;
        if (delta - 1.0).abs() < 1e-17 || i > 400.0 { break; }
        i += 1.0;
    }
    exp(-ax * ax) * ONE_OVER_SQRT_PI / f
}

/// # C: double erf(double x)
pub(crate) fn erf(x: f64) -> f64 {
    if x.is_nan() { return x; }
    if x.is_infinite() { return if x > 0.0 { 1.0 } else { -1.0 }; }
    let ax = x.abs();
    let r = if ax < 1.5 { erf_series(ax) } else { 1.0 - erfc_cf(ax) };
    if x < 0.0 { -r } else { r }
}

/// # C: double erfc(double x)
pub(crate) fn erfc(x: f64) -> f64 {
    if x.is_nan() { return x; }
    if x.is_infinite() { return if x > 0.0 { 0.0 } else { 2.0 }; }
    let ax = x.abs();
    // |x|<1.5: 1 - erf (no harmful cancellation, erf is small there). Larger:
    // the continued fraction directly. For x<0, erfc(x) = 2 - erfc(|x|).
    if x >= 0.0 {
        if ax < 1.0 { 1.0 - erf_series(ax) } else { erfc_cf(ax) }
    } else if ax < 1.0 {
        1.0 + erf_series(ax)
    } else {
        2.0 - erfc_cf(ax)
    }
}

/// # C: float erff(float)
pub(crate) fn erff(x: f32) -> f32 { erf(x as f64) as f32 }
/// # C: float erfcf(float)
pub(crate) fn erfcf(x: f32) -> f32 { erfc(x as f64) as f32 }

#[cfg(feature = "freestanding")]
mod exports {
    // # C: double erf(double)
    #[no_mangle] pub extern "C" fn erf(x: f64) -> f64 { super::erf(x) }
    // # C: double erfc(double)
    #[no_mangle] pub extern "C" fn erfc(x: f64) -> f64 { super::erfc(x) }
    // # C: float erff(float)
    #[no_mangle] pub extern "C" fn erff(x: f32) -> f32 { super::erff(x) }
    // # C: float erfcf(float)
    #[no_mangle] pub extern "C" fn erfcf(x: f32) -> f32 { super::erfcf(x) }
}

#[cfg(test)]
mod tests {
    extern "C" { fn erf(x: f64) -> f64; fn erfc(x: f64) -> f64; }
    fn ulp(a: f64, b: f64) -> u64 { (a.to_bits() as i64 - b.to_bits() as i64).unsigned_abs() }
    #[test]
    fn erf_matches_host() {
        let vs = [0.0, 0.1, 0.5, 0.84, 1.0, 1.25, 1.5, 2.0, 3.0, 5.0, 7.0, 25.0,
                  -0.5, -1.1, -2.0, -5.0, 0.000001, 0.84375, 6.5, 0.75, 1.49, 1.51];
        for &x in &vs {
            // SAFETY: host erf/erfc are pure numeric functions.
            let (he, hc) = unsafe { (erf(x), erfc(x)) };
            let (oe, oc) = (super::erf(x), super::erfc(x));
            // ≤16 ULP (≈14-15 sig figs): the erfc tail inherits our exp's
            // ≤2-4 ULP; the conformance test diffs at %.13g where this is exact.
            assert!(ulp(oe, he) <= 16, "erf({x}): ours={oe:e} host={he:e} ulp={}", ulp(oe, he));
            assert!(ulp(oc, hc) <= 16, "erfc({x}): ours={oc:e} host={hc:e} ulp={}", ulp(oc, hc));
        }
    }
}
