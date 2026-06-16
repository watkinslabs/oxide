/* C23 _FloatN aliases of the *pi/fmaximum/expN-m1 functions. vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <math.h>
int main(void) {
    printf("sinpi=%d %d\n", sinpif32(0.5f)==sinpif(0.5f), sinpif64(0.5)==sinpi(0.5));
    printf("fmax=%d %d\n", fmaximumf32(1.0f,2.0f)==fmaximumf(1.0f,2.0f), fmaximumf64(1.0,2.0)==fmaximum(1.0,2.0));
    printf("exp10m1=%d\n", exp10m1f64(0.0)==exp10m1(0.0));
    printf("acospi=%d\n", acospif64(1.0)==acospi(1.0));
    return 0;
}
