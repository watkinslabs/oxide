// fma(x,y,z) = round(x*y + z) with a SINGLE rounding (docs/59§6 G15). Software
// implementation via integer mantissa arithmetic: the 53×53→106-bit exact
// product is combined with z in a 128-bit normalized accumulator (larger
// operand's MSB at bit 127, smaller aligned with a guard/round/sticky tail),
// then rounded to nearest-even. No hardware FMA / no recursion into mul_add.

// value(x) = (-1)^sign * mant * 2^exp, mant the integer significand.
fn decomp(x: f64) -> (bool, u64, i32) {
    let b = x.to_bits();
    let neg = b >> 63 != 0;
    let ef = ((b >> 52) & 0x7ff) as i32;
    let frac = b & ((1u64 << 52) - 1);
    if ef == 0 { (neg, frac, -1074) } else { (neg, frac | (1u64 << 52), ef - 1075) }
}

// Round a 128-bit normalized magnitude (msb may be anywhere) at 2^exp (exp =
// weight of bit 0) into an f64 of the given sign. `sticky` folds in any bits
// already lost below bit 0. Round-to-nearest-even, with overflow→inf and
// gradual underflow.
fn pack(sign: bool, mut m: u128, mut exp: i32, mut sticky: bool) -> f64 {
    // An exactly-zero magnitude is the result of full cancellation: +0.0 in
    // round-to-nearest (IEEE 754 §6.3), regardless of the operand sign.
    if m == 0 { return 0.0; }
    // normalize so the MSB is at bit 127
    let lz = m.leading_zeros();
    m <<= lz; exp -= lz as i32;
    // now value = m * 2^exp, m in [2^127, 2^128). The leading 1 is bit 127.
    // We want 53 significant bits: bit 127..75. Unbiased exponent of the value
    // = exp + 127. Target f64 exponent field.
    let mut e = exp + 127; // exponent of the implicit leading 1
    // round 128-bit m to 53 bits (keep top 53, bits 127..75); round bit = 74,
    // sticky = OR(bits 73..0) | sticky.
    let round_bit = (m >> 74) & 1;
    let sticky_bits = (m & ((1u128 << 74) - 1)) != 0 || sticky;
    let mut mant = (m >> 75) as u64; // 53 bits (bit52..0)
    // round to nearest even
    if round_bit == 1 && (sticky_bits || (mant & 1) == 1) {
        mant += 1;
        if mant == (1u64 << 53) { mant >>= 1; e += 1; } // carry
    }
    // mant now in [2^52, 2^53). Build f64: biased exp = e + 1023.
    let biased = e + 1023;
    let s = (sign as u64) << 63;
    if biased >= 0x7ff { return f64::from_bits(s | (0x7ffu64 << 52)); } // overflow → inf
    if biased <= 0 {
        // subnormal / underflow: shift mant right by (1 - biased)
        let shift = 1 - biased;
        if shift >= 64 {
            sticky = sticky_bits || mant != 0;
            return f64::from_bits(s | (sticky as u64 & 0)); // ±0 (full underflow)
        }
        let lost = mant & ((1u64 << shift) - 1);
        let mut sub = mant >> shift;
        let rb = (mant >> (shift - 1)) & 1;
        let st = (lost & ((1u64 << (shift - 1)) - 1)) != 0 || sticky_bits;
        if rb == 1 && (st || (sub & 1) == 1) { sub += 1; }
        return f64::from_bits(s | sub);
    }
    f64::from_bits(s | ((biased as u64) << 52) | (mant & ((1u64 << 52) - 1)))
}

// shift m right by n, returning (shifted, sticky = any 1 lost).
fn shr_sticky(m: u128, n: u32) -> (u128, bool) {
    if n == 0 { return (m, false); }
    if n >= 128 { return (0, m != 0); }
    (m >> n, (m & ((1u128 << n) - 1)) != 0)
}

/// # C: double fma(double x, double y, double z) — single-rounding x*y+z
pub(crate) fn fma(x: f64, y: f64, z: f64) -> f64 {
    // Non-normal / zero cases: a plain expression is already correctly rounded
    // (the product is exact or the result is dominated by inf/nan/zero).
    if x == 0.0 || y == 0.0 || !x.is_finite() || !y.is_finite() || !z.is_finite() {
        return x * y + z;
    }
    let (xs, xm, xe) = decomp(x);
    let (ys, ym, ye) = decomp(y);
    let ps = xs ^ ys;
    let pm = (xm as u128) * (ym as u128); // exact product significand
    let pe = xe + ye;                     // weight of bit 0 of pm
    if z == 0.0 { return pack(ps, pm, pe, false); }
    let (zs, zm0, ze) = decomp(z);
    let zm = zm0 as u128;

    // Common exponent placing the larger operand's MSB near bit ~116, keeping
    // 64 guard bits below the result's LSB — so the round bit and ample sticky
    // are *real* retained bits in the u128 (correct rounding), and both
    // operands (≤106 / ≤53 bits) fit without overflow.
    let ptop = pe + (128 - pm.leading_zeros() as i32);
    let ztop = ze + (128 - zm.leading_zeros() as i32);
    let ebase = ptop.max(ztop) - 117;
    let place = |m: u128, e: i32| -> (u128, bool) {
        let s = e - ebase;
        if s >= 0 { (m << s, false) } else { shr_sticky(m, (-s) as u32) }
    };
    let (pv, p_st) = place(pm, pe);
    let (zv, z_st) = place(zm, ze);

    if ps == zs {
        pack(ps, pv + zv, ebase, p_st || z_st)
    } else if pv >= zv {
        // product larger: subtract z; z's lost tail (z_st) makes z a hair bigger
        // → borrow 1 (the freed low bits become real sticky in the u128).
        let m = pv - zv - (z_st as u128);
        pack(ps, m, ebase, p_st)
    } else {
        let m = zv - pv - (p_st as u128);
        pack(zs, m, ebase, z_st)
    }
}

/// # C: float fmaf(float x, float y, float z)
pub(crate) fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    // f32 inputs: the exact product fits in f64 (48 bits), so the f64 fma of
    // the promoted values is exact in the product and single-rounds the add;
    // narrowing to f32 is then the correctly-rounded result.
    fma(x as f64, y as f64, z as f64) as f32
}

#[cfg(feature = "freestanding")]
mod exports {
    // # C: double fma(double, double, double)
    #[no_mangle] pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 { super::fma(x, y, z) }
    // # C: float fmaf(float, float, float)
    #[no_mangle] pub extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 { super::fmaf(x, y, z) }
}

#[cfg(test)]
mod tests {
    extern "C" { fn fma(x: f64, y: f64, z: f64) -> f64; }
    // SAFETY: host libm fma is a pure numeric function with no preconditions.
    fn h(x: f64, y: f64, z: f64) -> u64 { unsafe { fma(x, y, z) }.to_bits() }
    #[test]
    fn matches_host() {
        let vs = [0.1, 0.2, 0.3, 1.0, -1.0, 2.5, 1e300, 1e-300, 3.14159, -2.71828,
                  123456.789, 0.0, -0.0, 1.0000000001, 9007199254740993.0, 1e-320];
        for &a in &vs { for &b in &vs { for &c in &vs {
            let ours = super::fma(a, b, c).to_bits();
            assert_eq!(ours, h(a, b, c), "fma({a},{b},{c}) ours={ours:#x} host={:#x}", h(a, b, c));
        }}}
    }
}
