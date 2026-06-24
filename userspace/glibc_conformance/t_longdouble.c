#include <complex.h>
#include <stdint.h>
#include <math.h>
#include <stdio.h>

extern int __finitel(long double);
extern int __isinfl(long double);
extern int __isnanl(long double);
extern int __signbitl(long double);
extern int __fpclassifyl(long double);
extern int __issignalingl(long double);
extern long double fmaxmagl(long double, long double);
extern long double fminmagl(long double, long double);
extern long double fmaximum_numl(long double, long double);
extern long double fminimum_numl(long double, long double);
extern long double fmaximuml(long double, long double);
extern long double fminimuml(long double, long double);
extern long double fmaximum_mag_numl(long double, long double);
extern long double fminimum_mag_numl(long double, long double);
extern long double fmaximum_magl(long double, long double);
extern long double fminimum_magl(long double, long double);
extern void sincosl(long double, long double *, long double *);
extern int totalorderl(const long double *, const long double *);
extern int totalordermagl(const long double *, const long double *);
extern int canonicalizel(long double *, const long double *);
extern long double getpayloadl(const long double *);
extern int setpayloadl(long double *, long double);
extern int setpayloadsigl(long double *, long double);
extern intmax_t fromfpl(long double, int, unsigned int);
extern uintmax_t ufromfpl(long double, int, unsigned int);
extern intmax_t fromfpxl(long double, int, unsigned int);
extern uintmax_t ufromfpxl(long double, int, unsigned int);

int main(void) {
    volatile long double neg = -2.5L;
    volatile long double pos = 1.0L;
    volatile long double mz = -0.0L;
    volatile long double zero = 0.0L;

    long double _Complex z;
    __real__ z = -3.0L;
    __imag__ z = 4.0L;
    long double _Complex cz = conjl(z);
    long double nanv = zero / zero;
    long double infv = pos / zero;
    long double _Complex ipz;
    __real__ ipz = 1.0L;
    __imag__ ipz = infv;
    long double _Complex inz;
    __real__ inz = infv;
    __imag__ inz = -2.0L;
    long double _Complex cpz = cprojl(ipz);
    long double _Complex cnz = cprojl(inz);
    long double whole = 0.0L;
    long double part = modfl(-2.75L, &whole);
    long double zw = 1.0L;
    long double zpart = modfl(mz, &zw);
    long double infw = 0.0L;
    long double infpart = modfl(-infv, &infw);
    long double nanw = 0.0L;
    long double nanpart = modfl(nanv, &nanw);
    long double scaled_zero = scalbnl(mz, 5);
    int frexp_e = 0;
    long double frexp_v = frexpl(-12.0L, &frexp_e);
    int frexp_ze = 99;
    long double frexp_zv = frexpl(mz, &frexp_ze);
    long double fmod_z = fmodl(-4.0L, 2.0L);
    long double rem_z = remainderl(-4.0L, 2.0L);
    unsigned char *nan1_bytes = (unsigned char *)&(long double){ nanl("1") };
    long double pnan = nanl("");
    long double nnan = -pnan;
    long double mzv = mz;
    long double zerov = zero;
    long double next_pos = nextafterl(0.0L, 1.0L);
    long double next_neg = nextafterl(0.0L, -1.0L);
    long double payload_q = 0.0L;
    long double payload_s = 0.0L;
    long double payload_bad = 123.0L;
    long double canon_dst = 0.0L;
    long double sincos_s = 0.0L;
    long double sincos_c = 0.0L;
    int setpayload_q_rc = setpayloadl(&payload_q, 42.0L);
    int setpayload_s_rc = setpayloadsigl(&payload_s, 42.0L);
    int setpayload_s0_rc = setpayloadsigl(&payload_bad, 0.0L);
    int canonicalize_rc = canonicalizel(&canon_dst, &(long double){3.5L});
    sincosl(0.5L, &sincos_s, &sincos_c);

    printf("sizeof_ld=%zu\n", sizeof(long double));
    printf("fabsl=%d\n", fabsl(neg) == 2.5L);
    printf("copysignl=%d\n", signbit(copysignl(pos, mz)) ? 1 : 0);
    printf("isnanl=%d\n", isnanl(nanv) ? 1 : 0);
    printf("isinfl=%d\n", isinfl(infv) ? 1 : 0);
    printf("finitel=%d/%d/%d\n", finitel(neg), finitel(infv), finitel(nanv));
    printf("__classify=%d/%d/%d/%d/%d/%d\n",
           __finitel(neg),
           __isinfl(infv) ? 1 : 0,
           __isnanl(nanv) ? 1 : 0,
           __signbitl(mz) ? 1 : 0,
           __fpclassifyl(zero),
           __issignalingl(nanv) ? 1 : 0);
    printf("complex_access=%d/%d/%d/%d\n",
           creall(z) == -3.0L,
           cimagl(z) == 4.0L,
           creall(cz) == -3.0L,
           cimagl(cz) == -4.0L);
    printf("cprojl=%d/%d/%d/%d\n",
           isinfl(creall(cpz)) ? 1 : 0,
           cimagl(cpz) == 0.0L,
           signbit(cimagl(cpz)) ? 1 : 0,
           signbit(cimagl(cnz)) ? 1 : 0);
    printf("rintl=%d/%d/%d\n",
           rintl(2.5L) == 2.0L,
           rintl(-1.5L) == -2.0L,
           signbit(rintl(mz)) ? 1 : 0);
    printf("x87_round=%d/%d/%d/%d/%d\n",
           ceill(1.2L) == 2.0L,
           ceill(-1.2L) == -1.0L,
           floorl(-1.2L) == -2.0L,
           truncl(-1.8L) == -1.0L,
           signbit(floorl(mz)) ? 1 : 0);
    printf("roundevenl=%d/%d/%d\n",
           roundevenl(2.5L) == 2.0L,
           roundevenl(3.5L) == 4.0L,
           signbit(roundevenl(mz)) ? 1 : 0);
    printf("round_batch=%d/%d/%d/%ld/%lld/%ld/%lld\n",
           nearbyintl(2.5L) == 2.0L,
           roundl(2.5L) == 3.0L,
           roundl(-2.5L) == -3.0L,
           lroundl(2.5L),
           llroundl(-2.5L),
           lrintl(2.5L),
           llrintl(-1.5L));
    printf("minmax_batch=%d/%d/%d/%d/%d/%d/%d\n",
           fmaxl(nanv, neg) == neg,
           signbit(fmaxl(mz, zero)) ? 1 : 0,
           signbit(fminl(mz, zero)) ? 1 : 0,
           fdiml(pos, neg) == 3.5L,
           fdiml(neg, pos) == 0.0L,
           fmaxmagl(-4.0L, 3.0L) == -4.0L,
           fminmagl(-4.0L, 3.0L) == 3.0L);
    printf("c23_minmax=%d/%d/%d/%d/%d/%d/%d/%d\n",
           fmaximum_numl(nanv, neg) == neg,
           fminimum_numl(nanv, neg) == neg,
           isnanl(fmaximuml(nanv, neg)) ? 1 : 0,
           isnanl(fminimuml(nanv, neg)) ? 1 : 0,
           fmaximum_mag_numl(-4.0L, 3.0L) == -4.0L,
           fminimum_mag_numl(-4.0L, 3.0L) == 3.0L,
           fmaximum_magl(-4.0L, 3.0L) == -4.0L,
           fminimum_magl(-4.0L, 3.0L) == 3.0L);
    printf("sqrtl=%d/%d/%d/%d\n",
           sqrtl(4.0L) == 2.0L,
           sqrtl(mz) == 0.0L,
           signbit(sqrtl(mz)) ? 1 : 0,
           isnanl(sqrtl(-1.0L)) ? 1 : 0);
    printf("hypot_abs=%d/%d/%d/%d/%d/%d\n",
           hypotl(3.0L, 4.0L) == 5.0L,
           hypotl(mz, zero) == 0.0L && !signbit(hypotl(mz, zero)),
           isinfl(hypotl(infv, nanv)) ? 1 : 0,
           isnanl(hypotl(nanv, 1.0L)) ? 1 : 0,
           cabsl(z) == 5.0L,
           isinfl(cabsl(ipz)) ? 1 : 0);
    printf("cbrtl=%d/%d/%d/%d/%d\n",
           cbrtl(27.0L) == 3.0L,
           cbrtl(-8.0L) == -2.0L,
           cbrtl(mz) == 0.0L && signbit(cbrtl(mz)),
           isinfl(cbrtl(-infv)) && signbit(cbrtl(-infv)),
           isnanl(cbrtl(nanv)) ? 1 : 0);
    printf("trig_l=%d/%d/%d/%d/%d/%d/%d/%d/%d\n",
           sinl(0.0L) == 0.0L && !signbit(sinl(0.0L)),
           cosl(0.0L) == 1.0L,
           tanl(0.0L) == 0.0L && !signbit(tanl(0.0L)),
           sincos_s == sinl(0.5L),
           sincos_c == cosl(0.5L),
           atanl(1.0L) == atan2l(1.0L, 1.0L),
           asinl(0.5L) > 0.0L && asinl(0.5L) < 1.0L,
           acosl(0.5L) > 1.0L && acosl(0.5L) < 2.0L,
           cargl(z) == atan2l(4.0L, -3.0L));
    printf("modfl=%d/%d/%d/%d/%d/%d/%d\n",
           part == -0.75L,
           whole == -2.0L,
           zpart == 0.0L,
           signbit(zpart) ? 1 : 0,
           isinfl(infw) && signbit(infw),
           infpart == 0.0L && signbit(infpart),
           isnanl(nanpart) && isnanl(nanw));
    printf("scale_batch=%d/%d/%d/%d/%d/%d\n",
           ldexpl(1.5L, 3) == 12.0L,
           scalbnl(-3.0L, -1) == -1.5L,
           scalblnl(2.0L, 10) == 2048.0L,
           scaled_zero == 0.0L && signbit(scaled_zero),
           isnanl(scalbnl(nanv, 3)) ? 1 : 0,
           isinfl(scalblnl(infv, -4)));
    printf("scalbl=%d/%d/%d/%d/%d\n",
           scalbl(3.0L, 2.0L) == 12.0L,
           scalbl(3.0L, -1.0L) == 1.5L,
           scaled_zero == 0.0L && signbit(scalbl(mz, 3.0L)),
           isnanl(scalbl(8.0L, 1.9L)) ? 1 : 0,
           isinfl(scalbl(infv, -2.0L)) ? 1 : 0);
    printf("exponent_batch=%d/%d/%d/%d/%d/%d/%d/%d/%d/%d\n",
           logbl(12.0L) == 3.0L,
           isinfl(logbl(zero)) && signbit(logbl(zero)),
           ilogbl(12.0L),
           ilogbl(zero) == (-2147483647 - 1),
           llogbl(infv) == __LONG_MAX__,
           frexp_v == -0.75L,
           frexp_e == 4,
           frexp_zv == 0.0L && signbit(frexp_zv) && frexp_ze == 0,
           significandl(12.0L) == 1.5L,
           isnanl(significandl(nanv)) ? 1 : 0);
    printf("remainder_batch=%d/%d/%d/%d/%d/%d/%d/%d/%d\n",
           fmodl(5.5L, 2.0L) == 1.5L,
           fmodl(-5.5L, 2.0L) == -1.5L,
           fmod_z == 0.0L && signbit(fmod_z),
           remainderl(5.5L, 2.0L) == -0.5L,
           remainderl(6.0L, 4.0L) == -2.0L,
           rem_z == 0.0L && signbit(rem_z),
           dreml(5.5L, 2.0L) == -0.5L,
           isnanl(fmodl(infv, 2.0L)) ? 1 : 0,
           isnanl(remainderl(2.0L, zero)) ? 1 : 0);
    printf("nanl=%d/%d/%u/%d\n",
           isnanl(nanl("")) ? 1 : 0,
           signbit(nanl("")) ? 1 : 0,
           (unsigned int)nan1_bytes[0],
           isnanl(nanl("bad")) ? 1 : 0);
    printf("totalorder=%d/%d/%d/%d/%d/%d/%d/%d\n",
           totalorderl(&(long double){1.0L}, &(long double){2.0L}),
           totalorderl(&(long double){2.0L}, &(long double){1.0L}),
           totalorderl(&mzv, &zerov),
           totalorderl(&zerov, &mzv),
           totalorderl(&nnan, &(long double){1.0L}),
           totalorderl(&(long double){1.0L}, &pnan),
           totalordermagl(&(long double){-3.0L}, &(long double){2.0L}),
           totalordermagl(&(long double){-2.0L}, &(long double){2.0L}));
    printf("next_batch=%d/%d/%d/%d/%d/%d/%d/%d/%d/%d\n",
           next_pos > 0.0L && !signbit(next_pos),
           next_neg < 0.0L && signbit(next_neg),
           nextafterl(1.0L, 2.0L) > 1.0L,
           nextafterl(1.0L, 0.0L) < 1.0L,
           nextafterl(-1.0L, -2.0L) < -1.0L,
           nextafterl(-1.0L, 0.0L) > -1.0L,
           nextupl(mz) > 0.0L,
           nextdownl(zero) < 0.0L,
           nexttoward(0.0, 1.0L) > 0.0,
           nexttowardf(-0.0f, -1.0L) < 0.0f);
    printf("payload_batch=%d/%d/%d/%d/%d/%d/%d/%d\n",
           setpayload_q_rc == 0,
           isnanl(payload_q) ? 1 : 0,
           getpayloadl(&payload_q) == 42.0L,
           setpayload_s_rc == 0,
           isnanl(payload_s) ? 1 : 0,
           getpayloadl(&payload_s) == 42.0L,
           setpayload_s0_rc == 1 && payload_bad == 0.0L,
           canonicalize_rc == 0 && canon_dst == 3.5L);
    printf("fromfp_l=%jd/%jd/%jd/%jd/%jd/%ju/%jd/%ju/%jd/%jd\n",
           fromfpl(2.5L, FP_INT_TONEAREST, 16),
           fromfpl(2.5L, FP_INT_UPWARD, 16),
           fromfpl(-2.5L, FP_INT_DOWNWARD, 16),
           fromfpl(200.0L, FP_INT_TONEAREST, 8),
           fromfpl(nanv, FP_INT_TONEAREST, 8),
           ufromfpl(-1.0L, FP_INT_TONEAREST, 8),
           fromfpxl(7.5L, FP_INT_TONEAREST, 16),
           ufromfpxl(200.7L, FP_INT_DOWNWARD, 8),
           fromfpl(infv, FP_INT_TONEAREST, 8),
           fromfpl(-infv, FP_INT_TONEAREST, 8));
    return 0;
}
