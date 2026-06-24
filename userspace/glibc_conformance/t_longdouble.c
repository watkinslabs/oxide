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

    long double nanv = zero / zero;
    long double infv = pos / zero;

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
    return 0;
}
