#include <stdio.h>
#include <math.h>
int main(void){
    printf("inf=%d nan=%d\n", isinf(INFINITY), isnan(NAN));
    printf("fmod=%.4f trunc=%.1f round=%.1f\n", fmod(10.0,3.0), trunc(-2.7), round(2.5));
    printf("cbrt=%.6f exp2=%.4f log2=%.4f\n", cbrt(27.0), exp2(10.0), log2(1024.0));
    printf("sinh=%.6f tanh=%.6f\n", sinh(1.0), tanh(0.5));
    printf("copysign=%.1f signbit=%d\n", copysign(3.0,-1.0), signbit(-0.0)!=0);
    return 0;
}
