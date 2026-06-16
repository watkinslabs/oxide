/* C23 fmaximum/fminimum family — NaN-propagating, -0<+0 ordered. vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <math.h>
#define B(x) ((x) ? 1 : 0)
int main(void) {
    printf("max=%d %d %d\n", fmaximum(2.0,3.0)==3.0, isnan(fmaximum(NAN,1.0)), signbit(fmaximum(-0.0,0.0))==0);
    printf("min=%d %d %d\n", fminimum(2.0,3.0)==2.0, isnan(fminimum(1.0,NAN)), signbit(fminimum(-0.0,0.0))==1);
    printf("maxnum=%d %d\n", fmaximum_num(NAN,5.0)==5.0, fmaximum_num(2.0,3.0)==3.0);
    printf("minnum=%d %d\n", fminimum_num(NAN,5.0)==5.0, fminimum_num(2.0,3.0)==2.0);
    printf("maxmag=%d %d\n", fmaximum_mag(-5.0,3.0)==-5.0, fmaximum_mag(2.0,-2.0)==2.0);
    printf("minmag=%d %d\n", fminimum_mag(-5.0,3.0)==3.0, fminimum_mag(2.0,-2.0)==-2.0);
    printf("magnum=%d %d\n", fmaximum_mag_num(NAN,-5.0)==-5.0, fminimum_mag_num(NAN,3.0)==3.0);
    printf("f32=%d %d\n", fmaximumf(1.0f,2.0f)==2.0f, fminimumf(1.0f,2.0f)==1.0f);
    return 0;
}
