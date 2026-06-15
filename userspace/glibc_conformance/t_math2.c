#include <stdio.h>
#include <math.h>
int main(void){
    printf("expm1=%.6f log1p=%.6f\n", expm1(0.5), log1p(0.5));
    printf("asin=%.6f acos=%.6f\n", asin(0.5), acos(0.5));
    printf("asinh=%.6f acosh=%.6f atanh=%.6f\n", asinh(1.0), acosh(2.0), atanh(0.5));
    printf("ldexp=%.1f frexp=", ldexp(1.5, 4));
    int e; double m = frexp(12.0, &e); printf("%.4f,%d\n", m, e);
    printf("fmin=%.1f fmax=%.1f fdim=%.1f\n", fmin(2.0,3.0), fmax(2.0,3.0), fdim(5.0,2.0));
    return 0;
}
