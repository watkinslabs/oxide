/* C99 <complex.h> vs host glibc, printed at %.12g (real+imag separately). Our
   ops are composed from the real libm; interior (non-branch-cut) arguments are
   chosen so principal values agree at 12 significant figures. */
#include <stdio.h>
#include <complex.h>

#define P(tag, z) printf("%s = %.12g %+.12gi\n", tag, creal(z), cimag(z))
#define Pf(tag, z) printf("%s = %.6g %+.6gi\n", tag, crealf(z), cimagf(z))

int main(void) {
    double complex z = 1.3 + 0.7 * I;
    double complex w = 0.4 - 0.9 * I;
    float  complex zf = 1.3f + 0.7f * I;

    printf("cabs = %.12g\n", cabs(z));
    printf("carg = %.12g\n", carg(z));
    printf("creal = %.12g cimag = %.12g\n", creal(z), cimag(z));
    P("conj", conj(z));
    P("cproj", cproj(z));

    P("cexp", cexp(z));
    P("clog", clog(z));
    P("csqrt", csqrt(z));
    P("cpow", cpow(z, w));

    P("csin", csin(z));
    P("ccos", ccos(z));
    P("ctan", ctan(z));

    P("csinh", csinh(z));
    P("ccosh", ccosh(z));
    P("ctanh", ctanh(z));

    P("casin", casin(w));
    P("cacos", cacos(w));
    P("catan", catan(w));

    P("casinh", casinh(w));
    P("cacosh", cacosh(2.0 + 0.5 * I));
    P("catanh", catanh(w));

    /* float variants at %.6g */
    printf("cabsf = %.6g cargf = %.6g\n", cabsf(zf), cargf(zf));
    Pf("conjf", conjf(zf));
    Pf("cexpf", cexpf(zf));
    Pf("clogf", clogf(zf));
    Pf("csqrtf", csqrtf(zf));
    Pf("csinf", csinf(zf));
    Pf("ccosf", ccosf(zf));
    Pf("ctanhf", ctanhf(zf));
    Pf("catanf", catanf(0.4f - 0.9f * I));
    return 0;
}
