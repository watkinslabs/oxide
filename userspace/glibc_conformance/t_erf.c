/* erf/erfc vs host glibc, printed at %.13g (our composite impl is ≤16 ULP,
   invisible at 13 significant figures). */
#include <stdio.h>
#include <math.h>
int main(void){
    double xs[] = {0.0, 0.1, 0.3, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 2.5, 3.0,
                   4.0, 5.0, -0.5, -1.0, -2.0, -3.5, 0.0001, 0.999, 1.001};
    for (size_t i=0;i<sizeof xs/sizeof xs[0];i++)
        printf("erf(%.4g)=%.13g erfc=%.13g\n", xs[i], erf(xs[i]), erfc(xs[i]));
    printf("erff=%.6g erfcf=%.6g\n", erff(1.5f), erfcf(1.5f));
    printf("inf: erf=%.1f erfc=%.1f nerf=%.1f nerfc=%.1f\n", erf(INFINITY), erfc(INFINITY), erf(-INFINITY), erfc(-INFINITY));
    return 0;
}
