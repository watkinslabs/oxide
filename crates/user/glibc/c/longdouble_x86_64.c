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
