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
