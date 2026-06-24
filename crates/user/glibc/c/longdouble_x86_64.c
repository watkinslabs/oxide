/*
 * x86_64 SysV long double ABI bridge.
 *
 * Rust has no stable extern-C type for the 80-bit x87 long double value used by
 * glibc on x86_64, so this file owns the small ABI-exact surface that must
 * receive or return long double directly. Keep these implementations
 * freestanding: xtask links this object into libc.so.6/libc.a without host
 * libc/libm.  Do not add __builtin_*l wrappers unless objdump shows no PLT
 * relocation back to the same public symbol; those become recursive exports.
 */

long double fabsl(long double x) {
    return __builtin_fabsl(x);
}

long double copysignl(long double x, long double y) {
    return __builtin_copysignl(x, y);
}

int isnanl(long double x) {
    return __builtin_isnan(x);
}

int isinfl(long double x) {
    return __builtin_isinf(x);
}

int finitel(long double x) {
    return __builtin_isfinite(x);
}

int __finitel(long double x) {
    return __builtin_isfinite(x);
}

int __isinfl(long double x) {
    return __builtin_isinf(x);
}

int __isnanl(long double x) {
    return __builtin_isnan(x);
}

int __signbitl(long double x) {
    return __builtin_signbit(x);
}

int __fpclassifyl(long double x) {
    return __builtin_fpclassify(0, 1, 4, 3, 2, x);
}

int __issignalingl(long double x) {
    return __builtin_issignaling(x);
}

long double creall(long double _Complex z) {
    return __real__ z;
}

long double cimagl(long double _Complex z) {
    return __imag__ z;
}

long double _Complex conjl(long double _Complex z) {
    long double _Complex r;
    __real__ r = __real__ z;
    __imag__ r = -__imag__ z;
    return r;
}

long double _Complex cprojl(long double _Complex z) {
    if (__builtin_isinf(__real__ z) || __builtin_isinf(__imag__ z)) {
        long double _Complex r;
        __real__ r = __builtin_infl();
        __imag__ r = __builtin_copysignl(0.0L, __imag__ z);
        return r;
    }
    return z;
}

long double rintl(long double x) {
    return __builtin_rintl(x);
}

static long double x87_round_mode(long double x, unsigned short mode) {
    unsigned short cw;
    unsigned short newcw;
    long double y;
    __asm__ __volatile__("fnstcw %0" : "=m"(cw));
    newcw = (unsigned short)((cw & (unsigned short)~0x0c00u) | mode);
    __asm__ __volatile__(
        "fldcw %2\n\t"
        "fldt %1\n\t"
        "frndint\n\t"
        "fstpt %0\n\t"
        "fldcw %3"
        : "=m"(y)
        : "m"(x), "m"(newcw), "m"(cw)
        : "st");
    return y;
}

long double ceill(long double x) {
    return x87_round_mode(x, 0x0800u);
}

long double floorl(long double x) {
    return x87_round_mode(x, 0x0400u);
}

long double truncl(long double x) {
    return x87_round_mode(x, 0x0c00u);
}

long double roundevenl(long double x) {
    return x87_round_mode(x, 0x0000u);
}

static long double round_awayl(long double x) {
    long double ax = __builtin_fabsl(x);
    long double y = x87_round_mode(ax + 0.5L, 0x0c00u);
    return __builtin_copysignl(y, x);
}

long double nearbyintl(long double x) {
    return x87_round_mode(x, 0x0000u);
}

long double roundl(long double x) {
    return round_awayl(x);
}

long int lroundl(long double x) {
    return (long int)round_awayl(x);
}

long long int llroundl(long double x) {
    return (long long int)round_awayl(x);
}

long int lrintl(long double x) {
    return (long int)__builtin_rintl(x);
}

long long int llrintl(long double x) {
    return (long long int)__builtin_rintl(x);
}

static long double fmax_corel(long double x, long double y) {
    if (__builtin_isnan(x)) {
        return y;
    }
    if (__builtin_isnan(y)) {
        return x;
    }
    return x > y ? x : y;
}

static long double fmin_corel(long double x, long double y) {
    if (__builtin_isnan(x)) {
        return y;
    }
    if (__builtin_isnan(y)) {
        return x;
    }
    return x <= y ? x : y;
}

long double fmaxl(long double x, long double y) {
    return fmax_corel(x, y);
}

long double fminl(long double x, long double y) {
    return fmin_corel(x, y);
}

long double fdiml(long double x, long double y) {
    if (__builtin_isnan(x) || __builtin_isnan(y)) {
        return x + y;
    }
    return x > y ? x - y : 0.0L;
}

long double fmaxmagl(long double x, long double y) {
    long double ax = __builtin_fabsl(x);
    long double ay = __builtin_fabsl(y);
    if (__builtin_isnan(x)) {
        return y;
    }
    if (__builtin_isnan(y)) {
        return x;
    }
    if (ax > ay) {
        return x;
    }
    if (ay > ax) {
        return y;
    }
    return fmax_corel(x, y);
}

long double fminmagl(long double x, long double y) {
    long double ax = __builtin_fabsl(x);
    long double ay = __builtin_fabsl(y);
    if (__builtin_isnan(x)) {
        return y;
    }
    if (__builtin_isnan(y)) {
        return x;
    }
    if (ax < ay) {
        return x;
    }
    if (ay < ax) {
        return y;
    }
    return fmin_corel(x, y);
}

static long double fmaximum_corel(long double x, long double y) {
    if (__builtin_isnan(x) || __builtin_isnan(y)) {
        return x + y;
    }
    return x > y ? x : y;
}

static long double fminimum_corel(long double x, long double y) {
    if (__builtin_isnan(x) || __builtin_isnan(y)) {
        return x + y;
    }
    return x <= y ? x : y;
}

long double fmaximum_numl(long double x, long double y) {
    return fmax_corel(x, y);
}

long double fminimum_numl(long double x, long double y) {
    return fmin_corel(x, y);
}

long double fmaximuml(long double x, long double y) {
    return fmaximum_corel(x, y);
}

long double fminimuml(long double x, long double y) {
    return fminimum_corel(x, y);
}

long double fmaximum_mag_numl(long double x, long double y) {
    long double ax = __builtin_fabsl(x);
    long double ay = __builtin_fabsl(y);
    if (__builtin_isnan(x)) {
        return y;
    }
    if (__builtin_isnan(y)) {
        return x;
    }
    if (ax > ay) {
        return x;
    }
    if (ay > ax) {
        return y;
    }
    return fmax_corel(x, y);
}

long double fminimum_mag_numl(long double x, long double y) {
    long double ax = __builtin_fabsl(x);
    long double ay = __builtin_fabsl(y);
    if (__builtin_isnan(x)) {
        return y;
    }
    if (__builtin_isnan(y)) {
        return x;
    }
    if (ax < ay) {
        return x;
    }
    if (ay < ax) {
        return y;
    }
    return fmin_corel(x, y);
}

long double fmaximum_magl(long double x, long double y) {
    long double ax = __builtin_fabsl(x);
    long double ay = __builtin_fabsl(y);
    if (__builtin_isnan(x) || __builtin_isnan(y)) {
        return x + y;
    }
    if (ax > ay) {
        return x;
    }
    if (ay > ax) {
        return y;
    }
    return fmaximum_corel(x, y);
}

long double fminimum_magl(long double x, long double y) {
    long double ax = __builtin_fabsl(x);
    long double ay = __builtin_fabsl(y);
    if (__builtin_isnan(x) || __builtin_isnan(y)) {
        return x + y;
    }
    if (ax < ay) {
        return x;
    }
    if (ay < ax) {
        return y;
    }
    return fminimum_corel(x, y);
}

static long double x87_sqrtl(long double x) {
    long double y;
    __asm__ __volatile__(
        "fldt %1\n\t"
        "fsqrt\n\t"
        "fstpt %0"
        : "=m"(y)
        : "m"(x)
        : "st");
    return y;
}

long double sqrtl(long double x) {
    return x87_sqrtl(x);
}

static long double hypot_valuel(long double x, long double y) {
    long double ax = __builtin_fabsl(x);
    long double ay = __builtin_fabsl(y);

    if (__builtin_isinf(ax) || __builtin_isinf(ay)) {
        return 1.0L / 0.0L;
    }
    if (__builtin_isnan(ax) || __builtin_isnan(ay)) {
        return ax + ay;
    }
    if (ay > ax) {
        long double tmp = ax;
        ax = ay;
        ay = tmp;
    }
    if (ay == 0.0L) {
        return ax;
    }

    long double ratio = ay / ax;
    return ax * x87_sqrtl(1.0L + ratio * ratio);
}

long double hypotl(long double x, long double y) {
    return hypot_valuel(x, y);
}

long double cabsl(long double _Complex z) {
    return hypot_valuel(__real__ z, __imag__ z);
}

long double modfl(long double value, long double *integer_part) {
    if (!__builtin_isfinite(value)) {
        *integer_part = value;
        if (__builtin_isinf(value)) {
            return __builtin_copysignl(0.0L, value);
        }
        return value + value;
    }

    long double whole = x87_round_mode(value, 0x0c00u);
    long double fraction = value - whole;
    *integer_part = whole;
    if (fraction == 0.0L) {
        return __builtin_copysignl(0.0L, value);
    }
    return fraction;
}

static long double x87_scalbnl(long double x, long double exponent) {
    long double y;
    __asm__ __volatile__(
        "fldt %2\n\t"
        "fldt %1\n\t"
        "fscale\n\t"
        "fstp %%st(1)\n\t"
        "fstpt %0"
        : "=m"(y)
        : "m"(x), "m"(exponent)
        : "st");
    return y;
}

long double ldexpl(long double value, int exponent) {
    return x87_scalbnl(value, (long double)exponent);
}

long double scalbnl(long double x, int n) {
    return x87_scalbnl(x, (long double)n);
}

long double scalblnl(long double x, long int n) {
    return x87_scalbnl(x, (long double)n);
}

long double scalbl(long double value, long double exponent) {
    if (__builtin_isfinite(exponent)) {
        long double whole = x87_round_mode(exponent, 0x0c00u);
        if (whole != exponent) {
            long double zero = 0.0L;
            return zero / zero;
        }
    }
    return x87_scalbnl(value, exponent);
}

static void x87_extractl(long double x, long double *significand, long double *exponent) {
    long double sig;
    long double exp;
    __asm__ __volatile__(
        "fldt %2\n\t"
        "fxtract\n\t"
        "fstpt %0\n\t"
        "fstpt %1"
        : "=m"(sig), "=m"(exp)
        : "m"(x)
        : "st");
    *significand = sig;
    *exponent = exp;
}

static long double finite_logbl(long double x) {
    long double sig;
    long double exp;
    x87_extractl(x, &sig, &exp);
    return exp;
}

long double logbl(long double x) {
    if (x == 0.0L) {
        long double zero = 0.0L;
        return -1.0L / zero;
    }
    if (!__builtin_isfinite(x)) {
        return x * x;
    }

    return finite_logbl(x);
}

int ilogbl(long double x) {
    if (x == 0.0L || __builtin_isnan(x)) {
        return -2147483647 - 1;
    }
    if (__builtin_isinf(x)) {
        return 2147483647;
    }
    return (int)finite_logbl(x);
}

long int llogbl(long double x) {
    if (x == 0.0L || __builtin_isnan(x)) {
        return -__LONG_MAX__ - 1L;
    }
    if (__builtin_isinf(x)) {
        return __LONG_MAX__;
    }
    return (long int)finite_logbl(x);
}

long double frexpl(long double value, int *exponent) {
    if (value == 0.0L || !__builtin_isfinite(value)) {
        *exponent = 0;
        return value;
    }

    long double sig;
    long double exp;
    x87_extractl(value, &sig, &exp);
    *exponent = (int)exp + 1;
    return x87_scalbnl(sig, -1.0L);
}

long double significandl(long double x) {
    if (x == 0.0L || !__builtin_isfinite(x)) {
        return x;
    }

    long double sig;
    long double exp;
    x87_extractl(x, &sig, &exp);
    return sig;
}

long double cbrtl(long double x) {
    if (x == 0.0L || !__builtin_isfinite(x)) {
        return x;
    }

    long double ax = __builtin_fabsl(x);
    long double sig;
    long double expv;
    x87_extractl(ax, &sig, &expv);

    int exp = (int)expv;
    int q = exp / 3;
    int rem = exp - q * 3;
    if (rem < 0) {
        rem += 3;
        q -= 1;
    }

    long double y = x87_scalbnl(1.0L, q);
    if (rem == 1) {
        y *= 1.2599210498948731647672106072782283506L;
    } else if (rem == 2) {
        y *= 1.5874010519681994747517056392723082604L;
    }

    for (unsigned int i = 0; i < 10; i += 1) {
        y = (2.0L * y + ax / (y * y)) / 3.0L;
    }
    return __builtin_copysignl(y, x);
}

static void x87_sincosl(long double x, long double *sinx, long double *cosx) {
    long double s;
    long double c;
    __asm__ __volatile__(
        "fldt %2\n\t"
        "fsincos\n\t"
        "fstpt %0\n\t"
        "fstpt %1"
        : "=m"(c), "=m"(s)
        : "m"(x)
        : "st");
    *sinx = s;
    *cosx = c;
}

long double sinl(long double x) {
    long double s;
    long double c;
    x87_sincosl(x, &s, &c);
    return s;
}

long double cosl(long double x) {
    long double s;
    long double c;
    x87_sincosl(x, &s, &c);
    return c;
}

void sincosl(long double x, long double *sinx, long double *cosx) {
    x87_sincosl(x, sinx, cosx);
}

long double tanl(long double x) {
    long double t;
    __asm__ __volatile__(
        "fldt %1\n\t"
        "fptan\n\t"
        "fstp %%st(0)\n\t"
        "fstpt %0"
        : "=m"(t)
        : "m"(x)
        : "st");
    return t;
}

static long double atan2_valuel(long double y, long double x) {
    long double a;
    __asm__ __volatile__(
        "fldt %2\n\t"
        "fldt %1\n\t"
        "fpatan\n\t"
        "fstpt %0"
        : "=m"(a)
        : "m"(x), "m"(y)
        : "st");
    return a;
}

long double atan2l(long double y, long double x) {
    return atan2_valuel(y, x);
}

long double atanl(long double x) {
    return atan2_valuel(x, 1.0L);
}

long double asinl(long double x) {
    return atan2_valuel(x, x87_sqrtl((1.0L - x) * (1.0L + x)));
}

long double acosl(long double x) {
    return atan2_valuel(x87_sqrtl((1.0L - x) * (1.0L + x)), x);
}

long double cargl(long double _Complex z) {
    return atan2_valuel(__imag__ z, __real__ z);
}

static long double exp2_valuel(long double x) {
    long double i = x87_round_mode(x, 0x0400u);
    long double f = x - i;
    long double y;
    __asm__ __volatile__(
        "fldt %2\n\t"
        "f2xm1\n\t"
        "fld1\n\t"
        "faddp\n\t"
        "fldt %1\n\t"
        "fxch %%st(1)\n\t"
        "fscale\n\t"
        "fstp %%st(1)\n\t"
        "fstpt %0"
        : "=m"(y)
        : "m"(i), "m"(f)
        : "st");
    return y;
}

static long double log2_valuel(long double x) {
    long double y;
    __asm__ __volatile__(
        "fld1\n\t"
        "fldt %1\n\t"
        "fyl2x\n\t"
        "fstpt %0"
        : "=m"(y)
        : "m"(x)
        : "st");
    return y;
}

long double exp2l(long double x) {
    return exp2_valuel(x);
}

long double expl(long double x) {
    return exp2_valuel(x * 1.4426950408889634073599246810018921374L);
}

long double exp10l(long double x) {
    return exp2_valuel(x * 3.3219280948873623478703194294893901759L);
}

long double pow10l(long double x) {
    return exp2_valuel(x * 3.3219280948873623478703194294893901759L);
}

long double expm1l(long double x) {
    return exp2_valuel(x * 1.4426950408889634073599246810018921374L) - 1.0L;
}

long double log2l(long double x) {
    return log2_valuel(x);
}

long double logl(long double x) {
    return log2_valuel(x) * 0.69314718055994530941723212145817656808L;
}

long double log10l(long double x) {
    return log2_valuel(x) * 0.30102999566398119521373889472449302677L;
}

long double log1pl(long double x) {
    return log2_valuel(1.0L + x) * 0.69314718055994530941723212145817656808L;
}

long double powl(long double base, long double power) {
    return exp2_valuel(power * log2_valuel(base));
}

long double sinhl(long double x) {
    long double ex = exp2_valuel(x * 1.4426950408889634073599246810018921374L);
    long double enx = 1.0L / ex;
    return (ex - enx) * 0.5L;
}

long double coshl(long double x) {
    long double ex = exp2_valuel(x * 1.4426950408889634073599246810018921374L);
    long double enx = 1.0L / ex;
    return (ex + enx) * 0.5L;
}

long double tanhl(long double x) {
    long double e2x = exp2_valuel(2.0L * x * 1.4426950408889634073599246810018921374L);
    return (e2x - 1.0L) / (e2x + 1.0L);
}

long double asinhl(long double x) {
    return log2_valuel(x + x87_sqrtl(x * x + 1.0L)) * 0.69314718055994530941723212145817656808L;
}

long double acoshl(long double x) {
    return log2_valuel(x + x87_sqrtl((x - 1.0L) * (x + 1.0L))) * 0.69314718055994530941723212145817656808L;
}

long double atanhl(long double x) {
    return 0.5L * log2_valuel((1.0L + x) / (1.0L - x)) * 0.69314718055994530941723212145817656808L;
}

static long double x87_fprem(long double x, long double y) {
    long double r;
    __asm__ __volatile__(
        "fldt %2\n\t"
        "fldt %1\n"
        "1:\n\t"
        "fprem\n\t"
        "fnstsw %%ax\n\t"
        "testw $0x0400, %%ax\n\t"
        "jnz 1b\n\t"
        "fstpt %0\n\t"
        "fstp %%st(0)"
        : "=m"(r)
        : "m"(x), "m"(y)
        : "ax", "cc", "st");
    return r;
}

static long double x87_fprem1(long double x, long double y) {
    long double r;
    __asm__ __volatile__(
        "fldt %2\n\t"
        "fldt %1\n"
        "1:\n\t"
        "fprem1\n\t"
        "fnstsw %%ax\n\t"
        "testw $0x0400, %%ax\n\t"
        "jnz 1b\n\t"
        "fstpt %0\n\t"
        "fstp %%st(0)"
        : "=m"(r)
        : "m"(x), "m"(y)
        : "ax", "cc", "st");
    return r;
}

long double fmodl(long double numerator, long double denominator) {
    return x87_fprem(numerator, denominator);
}

long double remainderl(long double numerator, long double denominator) {
    return x87_fprem1(numerator, denominator);
}

long double dreml(long double numerator, long double denominator) {
    return x87_fprem1(numerator, denominator);
}

static unsigned long long nan_payloadl(const char *tagp) {
    unsigned long long payload = 0;
    int base = 10;

    if (tagp == (const char *)0) {
        return 0;
    }
    if (tagp[0] == '0' && (tagp[1] == 'x' || tagp[1] == 'X')) {
        base = 16;
        tagp += 2;
    }
    while (*tagp != '\0') {
        unsigned int digit;
        if (*tagp >= '0' && *tagp <= '9') {
            digit = (unsigned int)(*tagp - '0');
        } else if (base == 16 && *tagp >= 'a' && *tagp <= 'f') {
            digit = (unsigned int)(*tagp - 'a' + 10);
        } else if (base == 16 && *tagp >= 'A' && *tagp <= 'F') {
            digit = (unsigned int)(*tagp - 'A' + 10);
        } else {
            return 0;
        }
        if (digit >= (unsigned int)base) {
            return 0;
        }
        payload = payload * (unsigned long long)base + (unsigned long long)digit;
        payload &= 0x3fffffffffffffffull;
        tagp += 1;
    }
    return payload;
}

long double nanl(const char *tagp) {
    union {
        long double value;
        unsigned char bytes[16];
    } u;
    unsigned long long sig = 0xc000000000000000ull | nan_payloadl(tagp);

    for (unsigned int i = 0; i < 16; i += 1) {
        u.bytes[i] = 0;
    }
    for (unsigned int i = 0; i < 8; i += 1) {
        u.bytes[i] = (unsigned char)(sig >> (i * 8));
    }
    u.bytes[8] = 0xffu;
    u.bytes[9] = 0x7fu;
    return u.value;
}

static int totalorder_finitel(long double x, long double y) {
    if (x < y) {
        return 1;
    }
    if (x > y) {
        return 0;
    }
    if (x == 0.0L && y == 0.0L) {
        return __builtin_signbit(x) || !__builtin_signbit(y);
    }
    return 1;
}

static int totalorder_valuel(long double xv, long double yv) {
    int x_nan = __builtin_isnan(xv);
    int y_nan = __builtin_isnan(yv);

    if (x_nan || y_nan) {
        int xs = __builtin_signbit(xv);
        int ys = __builtin_signbit(yv);
        if (x_nan && y_nan) {
            if (xs != ys) {
                return xs ? 1 : 0;
            }
            return 1;
        }
        if (x_nan) {
            return xs ? 1 : 0;
        }
        return ys ? 0 : 1;
    }
    return totalorder_finitel(xv, yv);
}

int totalorderl(const long double *x, const long double *y) {
    return totalorder_valuel(*x, *y);
}

int totalordermagl(const long double *x, const long double *y) {
    long double ax = __builtin_fabsl(*x);
    long double ay = __builtin_fabsl(*y);
    return totalorder_valuel(ax, ay);
}

static unsigned long long ld_sig(const unsigned char bytes[16]) {
    unsigned long long sig = 0;
    for (unsigned int i = 0; i < 8; i += 1) {
        sig |= (unsigned long long)bytes[i] << (i * 8);
    }
    return sig;
}

static void set_ld_sig(unsigned char bytes[16], unsigned long long sig) {
    for (unsigned int i = 0; i < 8; i += 1) {
        bytes[i] = (unsigned char)(sig >> (i * 8));
    }
}

static unsigned short ld_sign_exp(const unsigned char bytes[16]) {
    return (unsigned short)((unsigned short)bytes[8] | ((unsigned short)bytes[9] << 8));
}

static void set_ld_sign_exp(unsigned char bytes[16], unsigned short sign_exp) {
    bytes[8] = (unsigned char)sign_exp;
    bytes[9] = (unsigned char)(sign_exp >> 8);
}

static int ld_is_nan(long double x) {
    union {
        long double value;
        unsigned char bytes[16];
    } u;
    u.value = x;
    unsigned short exp = (unsigned short)(ld_sign_exp(u.bytes) & 0x7fffu);
    unsigned long long sig = ld_sig(u.bytes);
    return exp == 0x7fffu && (sig & 0x7fffffffffffffffull) != 0;
}

static void ld_step_mag(unsigned char bytes[16], int up) {
    unsigned short se = ld_sign_exp(bytes);
    unsigned short sign = (unsigned short)(se & 0x8000u);
    unsigned short exp = (unsigned short)(se & 0x7fffu);
    unsigned long long sig = ld_sig(bytes);

    if (up) {
        if (exp == 0) {
            if (sig == 0x7fffffffffffffffull) {
                exp = 1;
                sig = 0x8000000000000000ull;
            } else {
                sig += 1;
            }
        } else if (exp < 0x7fffu) {
            if (sig == 0xffffffffffffffffull) {
                exp += 1;
                sig = 0x8000000000000000ull;
            } else {
                sig += 1;
            }
        }
    } else {
        if (exp == 0) {
            sig -= 1;
        } else if (sig == 0x8000000000000000ull) {
            exp -= 1;
            sig = exp == 0 ? 0x7fffffffffffffffull : 0xffffffffffffffffull;
        } else {
            sig -= 1;
        }
    }

    set_ld_sig(bytes, sig);
    set_ld_sign_exp(bytes, (unsigned short)(sign | exp));
}

static long double nextafter_valuel(long double x, long double y) {
    union {
        long double value;
        unsigned char bytes[16];
    } u;

    if (ld_is_nan(x) || ld_is_nan(y)) {
        return x + y;
    }
    if (x == y) {
        return y;
    }
    u.value = x;
    if (x == 0.0L) {
        for (unsigned int i = 0; i < 16; i += 1) {
            u.bytes[i] = 0;
        }
        set_ld_sig(u.bytes, 1);
        set_ld_sign_exp(u.bytes, __builtin_signbit(y) ? 0x8000u : 0x0000u);
        return u.value;
    }

    int up = x > 0.0L ? y > x : y < x;
    ld_step_mag(u.bytes, up);
    return u.value;
}

long double nextafterl(long double x, long double y) {
    return nextafter_valuel(x, y);
}

long double nexttowardl(long double x, long double y) {
    return nextafter_valuel(x, y);
}

long double nextupl(long double x) {
    if (ld_is_nan(x)) {
        return x + x;
    }
    long double inf = 1.0L / 0.0L;
    return x == inf ? x : nextafter_valuel(x, inf);
}

long double nextdownl(long double x) {
    if (ld_is_nan(x)) {
        return x + x;
    }
    long double inf = 1.0L / 0.0L;
    return x == -inf ? x : nextafter_valuel(x, -inf);
}

static double nexttoward_double(double x, long double y) {
    union {
        double value;
        unsigned long long bits;
    } u;
    if (__builtin_isnan(x) || ld_is_nan(y)) {
        return x + (double)y;
    }
    if ((long double)x == y) {
        return (double)y;
    }
    u.value = x;
    if (x == 0.0) {
        u.bits = __builtin_signbit(y) ? 0x8000000000000001ull : 1ull;
        return u.value;
    }
    if ((x > 0.0) == (y > (long double)x)) {
        u.bits += 1;
    } else {
        u.bits -= 1;
    }
    return u.value;
}

static float nexttoward_float(float x, long double y) {
    union {
        float value;
        unsigned int bits;
    } u;
    if (__builtin_isnan(x) || ld_is_nan(y)) {
        return x + (float)y;
    }
    if ((long double)x == y) {
        return (float)y;
    }
    u.value = x;
    if (x == 0.0f) {
        u.bits = __builtin_signbit(y) ? 0x80000001u : 1u;
        return u.value;
    }
    if ((x > 0.0f) == (y > (long double)x)) {
        u.bits += 1;
    } else {
        u.bits -= 1;
    }
    return u.value;
}

double nexttoward(double x, long double y) {
    return nexttoward_double(x, y);
}

float nexttowardf(float x, long double y) {
    return nexttoward_float(x, y);
}

static int ld_unsupported_encoding(long double x) {
    union {
        long double value;
        unsigned char bytes[16];
    } u;
    u.value = x;
    unsigned short exp = (unsigned short)(ld_sign_exp(u.bytes) & 0x7fffu);
    unsigned long long sig = ld_sig(u.bytes);
    unsigned long long intbit = 0x8000000000000000ull;

    return exp != 0 && exp != 0x7fffu && (sig & intbit) == 0;
}

static int ld_payload_value(long double payload, unsigned long long *out) {
    long double max_payload = 4611686018427387903.0L;
    unsigned long long bits;

    if (__builtin_isnan(payload) || payload < 0.0L || payload > max_payload) {
        return 0;
    }
    bits = (unsigned long long)payload;
    if ((long double)bits != payload) {
        return 0;
    }
    *out = bits;
    return 1;
}

long double getpayloadl(const long double *x) {
    union {
        long double value;
        unsigned char bytes[16];
    } u;
    u.value = *x;
    unsigned short exp = (unsigned short)(ld_sign_exp(u.bytes) & 0x7fffu);
    unsigned long long sig = ld_sig(u.bytes);

    if (exp != 0x7fffu || (sig & 0x7fffffffffffffffull) == 0) {
        return -1.0L;
    }
    return (long double)(sig & 0x3fffffffffffffffull);
}

static int setpayload_valuel(long double *x, long double payload, int signaling) {
    union {
        long double value;
        unsigned char bytes[16];
    } u;
    unsigned long long bits;

    for (unsigned int i = 0; i < 16; i += 1) {
        u.bytes[i] = 0;
    }
    if (!ld_payload_value(payload, &bits) || (signaling && bits == 0)) {
        *x = u.value;
        return 1;
    }
    set_ld_sig(u.bytes, (signaling ? 0x8000000000000000ull : 0xc000000000000000ull) | bits);
    set_ld_sign_exp(u.bytes, 0x7fffu);
    *x = u.value;
    return 0;
}

int setpayloadl(long double *x, long double payload) {
    return setpayload_valuel(x, payload, 0);
}

int setpayloadsigl(long double *x, long double payload) {
    return setpayload_valuel(x, payload, 1);
}

int canonicalizel(long double *cx, const long double *x) {
    if (ld_unsupported_encoding(*x)) {
        return 1;
    }
    *cx = *x;
    return 0;
}

static long double fromfp_roundl(long double x, int rnd) {
    if (rnd == 0) {
        return x87_round_mode(x, 0x0800u);
    }
    if (rnd == 1) {
        return x87_round_mode(x, 0x0400u);
    }
    if (rnd == 2) {
        return x87_round_mode(x, 0x0c00u);
    }
    if (rnd == 3) {
        return round_awayl(x);
    }
    return x87_round_mode(x, 0x0000u);
}

static long int fromfp_valuel(long double x, int rnd, unsigned int width) {
    unsigned int w = width > 64u ? 64u : width;
    long int hi;
    long int lo;
    long double r;

    if (w == 0) {
        return 0;
    }
    if (w >= 64u) {
        hi = __LONG_MAX__;
        lo = -__LONG_MAX__ - 1L;
    } else {
        hi = (long int)((1ull << (w - 1u)) - 1ull);
        lo = -(long int)(1ull << (w - 1u));
    }
    if (__builtin_isnan(x) || (__builtin_isinf(x) && x < 0.0L)) {
        return lo;
    }
    if (__builtin_isinf(x)) {
        return hi;
    }

    r = fromfp_roundl(x, rnd);
    if (r >= (long double)hi) {
        return hi;
    }
    if (r <= (long double)lo) {
        return lo;
    }
    return (long int)r;
}

static unsigned long int ufromfp_valuel(long double x, int rnd, unsigned int width) {
    unsigned int w = width > 64u ? 64u : width;
    unsigned long int hi;
    long double r;

    if (w == 0) {
        return 0;
    }
    hi = w >= 64u ? ~0ul : ((1ul << w) - 1ul);
    if (__builtin_isnan(x) || (__builtin_isinf(x) && x < 0.0L)) {
        return 0;
    }
    if (__builtin_isinf(x)) {
        return hi;
    }

    r = fromfp_roundl(x, rnd);
    if (r <= 0.0L) {
        return 0;
    }
    if (r >= (long double)hi) {
        return hi;
    }
    return (unsigned long int)r;
}

long int fromfpl(long double x, int rnd, unsigned int width) {
    return fromfp_valuel(x, rnd, width);
}

unsigned long int ufromfpl(long double x, int rnd, unsigned int width) {
    return ufromfp_valuel(x, rnd, width);
}

long int fromfpxl(long double x, int rnd, unsigned int width) {
    return fromfp_valuel(x, rnd, width);
}

unsigned long int ufromfpxl(long double x, int rnd, unsigned int width) {
    return ufromfp_valuel(x, rnd, width);
}
