/* C23 *pi trig + *m1/*p1: exact at special points, ~ULP elsewhere. vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <math.h>
#define NEAR(a,b) (fabs((a)-(b)) < 1e-9)
int main(void) {
    /* exact special points */
    printf("sinpi=%d %d %d\n", sinpi(0.5)==1.0, sinpi(1.0)==0.0, sinpi(1.5)==-1.0);
    printf("cospi=%d %d\n", cospi(0.5)==0.0, cospi(0.0)==1.0);
    printf("tanpi=%d\n", tanpi(0.0)==0.0);
    /* general (tolerance) */
    printf("gen=%d %d %d\n", NEAR(sinpi(0.25),sin(M_PI*0.25)), NEAR(cospi(0.25),cos(M_PI*0.25)),
           NEAR(atanpi(1.0),0.25));
    printf("inv=%d %d\n", acospi(1.0)==0.0, NEAR(asinpi(1.0),0.5));
    printf("atan2pi=%d\n", NEAR(atan2pi(1.0,1.0),0.25));
    /* m1/p1 */
    printf("m1=%d %d %d\n", exp2m1(0.0)==0.0, exp10m1(0.0)==0.0, NEAR(exp2m1(3.0),7.0));
    printf("p1=%d %d\n", log10p1(0.0)==0.0, NEAR(log10p1(9.0),1.0));
    printf("f32=%d\n", sinpif(0.5f)==1.0f);
    return 0;
}
