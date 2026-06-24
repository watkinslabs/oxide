#include <complex.h>
#include <math.h>
#include <stdio.h>

extern int __finitel(long double);
extern int __isinfl(long double);
extern int __isnanl(long double);
extern int __signbitl(long double);
extern int __fpclassifyl(long double);
extern int __issignalingl(long double);

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
    return 0;
}
