/* t_mathx — exercises the glibc math "extras" cluster (docs/59§6 G15):
 * integer rounding (lrint/llround/roundeven across .5 ties — round-half-to-even
 * vs round-half-away), classification ints (isinf/isnan/signbit/finite),
 * exp10/sincosf at %.13g, nextup/nextdown via raw bits, the C23 fromfp/ufromfp
 * round-to-integral, total-order predicates as bools, and nan("123") payload.
 * Diffed byte-for-byte against host glibc by xtask glibc-test. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <inttypes.h>
#include <fenv.h>

/* scalb is deprecated and no longer prototyped by modern <math.h>; declare it
 * explicitly (the symbol still exists in libm / our libc). pow10 was dropped
 * from glibc 2.41 entirely, so it is exercised only via its exp10 alias. */
extern double scalb(double, double);
extern float scalbf(float, float);

int main(void) {
    /* default round-to-nearest for lrint */
    fesetround(FE_TONEAREST);

    /* round-half-to-even: lrint/llrint/roundeven */
    printf("lrint: %ld %ld %ld %ld %ld\n",
           lrint(0.5), lrint(1.5), lrint(2.5), lrint(-2.5), lrint(3.5));
    printf("llrint: %lld %lld\n", llrint(2.5), llrint(-3.5));
    printf("roundeven: %.1f %.1f %.1f %.1f\n",
           roundeven(0.5), roundeven(1.5), roundeven(2.5), roundeven(-2.5));
    printf("roundevenf: %.1f %.1f\n", roundevenf(2.5f), roundevenf(3.5f));

    /* round-half-away: lround/llround */
    printf("lround: %ld %ld %ld %ld\n",
           lround(0.5), lround(2.5), lround(-2.5), lround(-0.5));
    printf("llround: %lld %lld\n", llround(2.5), llround(-2.5));
    printf("lrintf/lroundf: %ld %ld\n", lrintf(2.5f), lroundf(2.5f));

    /* classification as ints */
    printf("isinf: %d %d %d\n", isinf(INFINITY), isinf(-INFINITY), isinf(1.0));
    printf("isnan: %d %d\n", isnan(NAN), isnan(1.0));
    printf("signbit: %d %d %d\n", signbit(-1.0) ? 1 : 0,
           signbit(1.0) ? 1 : 0, signbit(-0.0) ? 1 : 0);
    printf("finite: %d %d %d\n", finite(1.0), finite(INFINITY), finite(NAN));
    printf("finitef: %d %d\n", finitef(1.0f), finitef(INFINITY));

    /* exp10/pow10 at %.13g */
    printf("exp10: %.13g %.13g %.13g %.13g\n",
           exp10(0.0), exp10(3.0), exp10(7.3), exp10(-2.5));
    printf("exp10big: %.13g %.13g\n", exp10(100.0), exp10(-100.0));
    printf("exp10f: %.7g %.7g\n", exp10f(2.0f), exp10f(0.5f));

    /* sincosf at %.13g */
    float fs, fc;
    sincosf(1.0f, &fs, &fc);
    printf("sincosf: %.7g %.7g\n", fs, fc);
    double ds, dc;
    sincos(1.0, &ds, &dc);
    printf("sincos: %.13g %.13g\n", ds, dc);

    /* nextup/nextdown via the bit pattern */
    double nu = nextup(1.0), nd = nextdown(1.0);
    printf("nextup/down bits: %016lx %016lx\n",
           (unsigned long)*(uint64_t *)&nu, (unsigned long)*(uint64_t *)&nd);
    float fnu = nextupf(1.0f), fnd = nextdownf(1.0f);
    printf("nextupf/downf bits: %08x %08x\n",
           *(uint32_t *)&fnu, *(uint32_t *)&fnd);
    double nuz = nextup(0.0);
    printf("nextup0 bits: %016lx\n", (unsigned long)*(uint64_t *)&nuz);

    /* scalb / significand / llogb */
    printf("scalb: %.1f %.1f\n", scalb(1.5, 4.0), scalbf(3.0f, 2.0f));
    printf("significand: %.4f %.4f\n", significand(12.0), significand(40.0));
    printf("llogb: %ld %ld\n", (long)llogb(8.0), (long)llogbf(0.25f));

    /* fromfp/ufromfp return intmax_t/uintmax_t (round-to-integral, saturating) */
    printf("fromfp: %jd %jd %jd %jd %jd\n",
           fromfp(2.5, FP_INT_TONEAREST, 16), fromfp(2.5, FP_INT_UPWARD, 16),
           fromfp(2.5, FP_INT_DOWNWARD, 16), fromfp(2.5, FP_INT_TOWARDZERO, 16),
           fromfp(2.5, FP_INT_TONEARESTFROMZERO, 16));
    printf("ufromfp: %ju\n", ufromfp(200.7, FP_INT_DOWNWARD, 8));
    printf("fromfp_sat: %jd %ju %jd %jd\n",
           fromfp(200.0, FP_INT_TONEAREST, 8), ufromfp(-1.0, FP_INT_TONEAREST, 8),
           fromfp(-200.0, FP_INT_TONEAREST, 8), fromfp(INFINITY, FP_INT_TONEAREST, 8));
    printf("fromfpf: %jd\n", fromfpf(5.5f, FP_INT_TONEARESTFROMZERO, 8));
    printf("fromfpx: %jd ufromfpx: %ju\n",
           fromfpx(7.5, FP_INT_TONEAREST, 16), ufromfpx(7.5, FP_INT_TONEAREST, 16));

    /* total-order predicates as bools */
    double a = -INFINITY, b = 1.0, z0 = -0.0, z1 = 0.0;
    printf("totalorder: %d %d %d %d\n",
           totalorder(&a, &b), totalorder(&b, &a),
           totalorder(&z0, &z1), totalorder(&z1, &z0));
    double m5 = -5.0, p3 = 3.0;
    printf("totalordermag: %d %d\n",
           totalordermag(&m5, &p3), totalordermag(&p3, &m5));

    /* nan("123") payload via the bits */
    double q = nan("123");
    printf("nan123 bits: %016lx isnan=%d\n",
           (unsigned long)*(uint64_t *)&q, isnan(q) ? 1 : 0);
    double qx = nan("0x2a");
    printf("nanhex bits: %016lx\n", (unsigned long)*(uint64_t *)&qx);
    float qf = nanf("7");
    printf("nanf bits: %08x\n", *(uint32_t *)&qf);

    /* getpayload / setpayload roundtrip */
    double pn;
    int rc = setpayload(&pn, 42.0);
    printf("setpayload: rc=%d payload=%.1f isnan=%d\n",
           rc, getpayload(&pn), isnan(pn) ? 1 : 0);

    /* canonicalize */
    double cx, src = 3.5;
    canonicalize(&cx, &src);
    printf("canonicalize: %.1f\n", cx);

    /* log1pf */
    printf("log1pf: %.7g\n", log1pf(0.5f));
    return 0;
}
