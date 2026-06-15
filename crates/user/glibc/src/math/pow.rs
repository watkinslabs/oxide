// math/pow — pow/powf (docs/59§6 G15). Faithful port of fdlibm e_pow.c:
// 2^(y·log2(x)) with double-double extra-precision tracking through the log,
// the multiply, and the exp (~≤1 ULP), plus the full C99 special-case rules.
// Pure no-std; differentially tested vs host libm + an exhaustive edge table.
#![allow(clippy::excessive_precision, clippy::needless_range_loop, clippy::approx_constant)]
use super::basic::scalbn;
use super::sqrt::sqrt;

const BP: [f64; 2] = [1.0, 1.5];
const DP_H: [f64; 2] = [0.0, 5.84962487220764160156e-01];
const DP_L: [f64; 2] = [0.0, 1.35003920212974897128e-08];
const TWO53: f64 = 9007199254740992.0;
const HUGE: f64 = 1.0e300;
const TINY: f64 = 1.0e-300;
const L1: f64 = 5.99999999999994648725e-01;
const L2: f64 = 4.28571428578550184252e-01;
const L3: f64 = 3.33333329818377432918e-01;
const L4: f64 = 2.72728123808534006489e-01;
const L5: f64 = 2.30660745775561366331e-01;
const L6: f64 = 2.06975017800338417784e-01;
const P1: f64 = 1.66666666666666019037e-01;
const P2: f64 = -2.77777777770155933842e-03;
const P3: f64 = 6.61375632143793436117e-05;
const P4: f64 = -1.65339022054652515390e-06;
const P5: f64 = 4.13813679705723846039e-08;
const LG2: f64 = 6.93147180559945286227e-01;
const LG2_H: f64 = 6.93147182464599609375e-01;
const LG2_L: f64 = -1.90465429995776804525e-09;
const OVT: f64 = 8.0085662595372944372e-17;
const CP: f64 = 9.61796693925975554329e-01;
const CP_H: f64 = 9.61796700954437255859e-01;
const CP_L: f64 = -7.02846165095275826516e-09;
const IVLN2: f64 = 1.44269504088896338700e+00;
const IVLN2_H: f64 = 1.44269502162933349609e+00;
const IVLN2_L: f64 = 1.92596299112661746887e-08;

#[inline]
fn hi(x: f64) -> i32 { (x.to_bits() >> 32) as u32 as i32 }
#[inline]
fn lo(x: f64) -> u32 { x.to_bits() as u32 }
#[inline]
fn set_hi(x: f64, h: i32) -> f64 { f64::from_bits((x.to_bits() & 0x0000_0000_ffff_ffff) | (((h as u32) as u64) << 32)) }
#[inline]
fn set_lo(x: f64, l: u32) -> f64 { f64::from_bits((x.to_bits() & 0xffff_ffff_0000_0000) | l as u64) }
#[inline]
fn fabs(x: f64) -> f64 { f64::from_bits(x.to_bits() & 0x7fff_ffff_ffff_ffff) }

/// # C: double pow(double x, double y)
pub(crate) fn pow(x: f64, y: f64) -> f64 {
    let (hx, lx) = (hi(x), lo(x));
    let (hy, ly) = (hi(y), lo(y));
    let mut ix = hx & 0x7fff_ffff;
    let iy = hy & 0x7fff_ffff;
    // y == 0 → 1 (incl y==NaN per C99: handled by the x==1 rule below + here)
    if (iy as u32 | ly) == 0 { return 1.0; }
    // pow(+1, y) == 1 for any y, including NaN (C99/POSIX)
    if hx == 0x3ff00000 && lx == 0 { return 1.0; }
    // x or y is NaN
    if ix > 0x7ff00000 || (ix == 0x7ff00000 && lx != 0) || iy > 0x7ff00000 || (iy == 0x7ff00000 && ly != 0) {
        return x + y;
    }
    // yisint: 0 = not int, 1 = odd int, 2 = even int (only matters for x<0)
    let mut yisint = 0i32;
    if hx < 0 {
        if iy >= 0x43400000 {
            yisint = 2;
        } else if iy >= 0x3ff00000 {
            let k = (iy >> 20) - 0x3ff;
            if k > 20 {
                let j = ly >> (52 - k);
                if (j << (52 - k)) == ly { yisint = 2 - (j & 1) as i32; }
            } else if ly == 0 {
                let j = iy >> (20 - k);
                if (j << (20 - k)) == iy { yisint = 2 - (j & 1); }
            }
        }
    }
    // special y
    if ly == 0 {
        if iy == 0x7ff00000 {
            if ((ix - 0x3ff00000) | lx as i32) == 0 { return 1.0; } // (±1)^±inf
            if ix >= 0x3ff00000 { return if hy >= 0 { y } else { 0.0 }; }
            return if hy < 0 { -y } else { 0.0 };
        }
        if iy == 0x3ff00000 { return if hy >= 0 { x } else { 1.0 / x }; } // y=±1
        if hy == 0x40000000 { return x * x; } // y=2
        if hy == 0x3fe00000 && hx >= 0 { return sqrt(x); } // y=0.5, x>=0
    }
    let mut ax = fabs(x);
    // special x: ±0, ±inf, ±1
    if lx == 0 && (ix == 0x7ff00000 || ix == 0 || ix == 0x3ff00000) {
        let mut z = ax;
        if hy < 0 { z = 1.0 / z; }
        if hx < 0 {
            if ((ix - 0x3ff00000) | yisint) == 0 { z = f64::NAN; } // (-1)^non-int
            else if yisint == 1 { z = -z; }
        }
        return z;
    }
    // sign of result
    let mut s = 1.0f64;
    if hx < 0 {
        if yisint == 0 { return f64::NAN; } // (-ve)^(non-int)
        if yisint == 1 { s = -1.0; }
    }

    let (t1, t2);
    if iy > 0x41e00000 {
        // |y| > 2^31
        if iy > 0x43f00000 {
            if ix <= 0x3fefffff { return if hy < 0 { HUGE * HUGE } else { TINY * TINY }; }
            if ix >= 0x3ff00000 { return if hy > 0 { HUGE * HUGE } else { TINY * TINY }; }
        }
        if ix < 0x3fefffff { return if hy < 0 { s * HUGE * HUGE } else { s * TINY * TINY }; }
        if ix > 0x3ff00000 { return if hy > 0 { s * HUGE * HUGE } else { s * TINY * TINY }; }
        let t = ax - 1.0;
        let w = (t * t) * (0.5 - t * (0.3333333333333333 - t * 0.25));
        let u = IVLN2_H * t;
        let v = t * IVLN2_L - w * IVLN2;
        let mut tt1 = u + v;
        tt1 = set_lo(tt1, 0);
        t1 = tt1;
        t2 = v - (t1 - u);
    } else {
        let mut n;
        if ix < 0x00100000 { ax *= TWO53; n = -53; ix = hi(ax); } else { n = 0; }
        n += (ix >> 20) - 0x3ff;
        let j = ix & 0x000fffff;
        ix = j | 0x3ff00000;
        let k;
        if j <= 0x3988E { k = 0; } else if j < 0xBB67A { k = 1; } else { k = 0; n += 1; ix -= 0x00100000; }
        ax = set_hi(ax, ix);
        let u = ax - BP[k as usize];
        let v = 1.0 / (ax + BP[k as usize]);
        let ss = u * v;
        let mut s_h = ss;
        s_h = set_lo(s_h, 0);
        let mut t_h = 0.0f64;
        t_h = set_hi(t_h, ((ix >> 1) | 0x20000000) + 0x00080000 + (k << 18));
        let t_l = ax - (t_h - BP[k as usize]);
        let s_l = v * ((u - s_h * t_h) - s_h * t_l);
        let s2 = ss * ss;
        let mut r = s2 * s2 * (L1 + s2 * (L2 + s2 * (L3 + s2 * (L4 + s2 * (L5 + s2 * L6)))));
        r += s_l * (s_h + ss);
        let s2b = s_h * s_h;
        let mut t_hb = 3.0 + s2b + r;
        t_hb = set_lo(t_hb, 0);
        let t_lb = r - ((t_hb - 3.0) - s2b);
        let u2 = s_h * t_hb;
        let v2 = s_l * t_hb + t_lb * ss;
        let mut p_h = u2 + v2;
        p_h = set_lo(p_h, 0);
        let p_l = v2 - (p_h - u2);
        let z_h = CP_H * p_h;
        let z_l = CP_L * p_h + p_l * CP + DP_L[k as usize];
        let t = n as f64;
        let mut tt1 = ((z_h + z_l) + DP_H[k as usize]) + t;
        tt1 = set_lo(tt1, 0);
        t1 = tt1;
        t2 = z_l - (((t1 - t) - DP_H[k as usize]) - z_h);
    }

    // (y1+y2)*(t1+t2)
    let mut y1 = y;
    y1 = set_lo(y1, 0);
    let p_l = (y - y1) * t1 + y * t2;
    let mut p_h = y1 * t1;
    let z = p_l + p_h;
    let j0 = hi(z);
    let i0 = lo(z);
    if j0 >= 0x40900000 {
        if ((j0 - 0x40900000) | i0 as i32) != 0 { return s * HUGE * HUGE; }
        if p_l + OVT > z - p_h { return s * HUGE * HUGE; }
    } else if (j0 & 0x7fffffff) >= 0x4090cc00 {
        if ((j0.wrapping_sub(0xc090cc00u32 as i32)) | i0 as i32) != 0 { return s * TINY * TINY; }
        if p_l <= z - p_h { return s * TINY * TINY; }
    }
    // 2^(p_h+p_l)
    let i = j0 & 0x7fffffff;
    let mut k = (i >> 20) - 0x3ff;
    let mut n = 0i32;
    if i > 0x3fe00000 {
        n = j0 + (0x00100000 >> (k + 1));
        k = ((n & 0x7fffffff) >> 20) - 0x3ff;
        let mut t = 0.0f64;
        t = set_hi(t, n & !(0x000fffff >> k));
        n = ((n & 0x000fffff) | 0x00100000) >> (20 - k);
        if j0 < 0 { n = -n; }
        p_h -= t;
    }
    let mut t = p_l + p_h;
    t = set_lo(t, 0);
    let u = t * LG2_H;
    let v = (p_l - (t - p_h)) * LG2 + t * LG2_L;
    let mut z = u + v;
    let w = v - (z - u);
    let tt = z * z;
    let t1b = z - tt * (P1 + tt * (P2 + tt * (P3 + tt * (P4 + tt * P5))));
    let r = (z * t1b) / (t1b - 2.0) - (w + z * w);
    z = 1.0 - (r - z);
    let mut jj = hi(z);
    jj += n << 20;
    if (jj >> 20) <= 0 {
        z = scalbn(z, n);
    } else {
        z = set_hi(z, jj);
    }
    s * z
}

/// # C: float powf(float, float)
pub(crate) fn powf(x: f32, y: f32) -> f32 { pow(x as f64, y as f64) as f32 }

#[cfg(feature = "freestanding")]
mod exports {
    #[no_mangle]
    pub extern "C" fn pow(x: f64, y: f64) -> f64 { super::pow(x, y) }
    #[no_mangle]
    pub extern "C" fn powf(x: f32, y: f32) -> f32 { super::powf(x, y) }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    extern "C" { fn pow(x: f64, y: f64) -> f64; }
    fn ulp(a: f64, b: f64) -> u64 {
        if a == b || (a.is_nan() && b.is_nan()) { return 0; }
        ((a.to_bits() as i64) - (b.to_bits() as i64)).unsigned_abs()
    }

    proptest! {
        #[test]
        fn pow_matches_host(x in 1e-3f64..100.0, y in -20.0f64..20.0) {
            // SAFETY: host libm pow() extern call, scalar f64 in/out.
            let h = unsafe { pow(x, y) };
            prop_assert!(ulp(super::pow(x, y), h) <= 4, "pow({},{})={} vs {}", x, y, super::pow(x, y), h);
        }
    }

    #[test]
    fn pow_edges() {
        let p = super::pow;
        assert_eq!(p(2.0, 10.0), 1024.0);
        assert_eq!(p(-2.0, 3.0), -8.0);
        assert_eq!(p(-2.0, 2.0), 4.0);
        assert!(p(-2.0, 0.5).is_nan());
        assert_eq!(p(0.0, -1.0), f64::INFINITY);
        assert_eq!(p(0.0, 3.0), 0.0);
        assert_eq!(p(0.0, -2.0), f64::INFINITY);
        assert_eq!(p(1.0, f64::NAN), 1.0);
        assert_eq!(p(f64::NAN, 0.0), 1.0);
        assert_eq!(p(f64::INFINITY, 0.5), f64::INFINITY);
        assert_eq!(p(0.5, f64::INFINITY), 0.0);
        assert_eq!(p(2.0, f64::INFINITY), f64::INFINITY);
        assert_eq!(p(-1.0, f64::INFINITY), 1.0);
        assert!(ulp(p(9.0, 0.5), 3.0) <= 1);
    }
}
