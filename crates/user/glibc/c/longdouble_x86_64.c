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

long double sqrtl(long double x) {
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
