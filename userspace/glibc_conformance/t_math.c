#include <stdio.h>
#include <math.h>
int main(void){
    printf("sqrt=%.6f pow=%.6f\n", sqrt(2.0), pow(2.0,10.0));
    printf("sin=%.6f cos=%.6f tan=%.6f\n", sin(1.0), cos(1.0), tan(0.5));
    printf("exp=%.6f log=%.6f log10=%.6f\n", exp(1.0), log(10.0), log10(1000.0));
    printf("floor=%.1f ceil=%.1f fabs=%.1f\n", floor(3.7), ceil(3.2), fabs(-5.0));
    printf("atan2=%.6f hypot=%.6f\n", atan2(1.0,1.0), hypot(3.0,4.0));
    return 0;
}
