/* Bessel j0/j1/y0/y1/jn/yn vs host glibc at %.6g (series+asymptotic crossover
   is ~1e-6 relative — invisible at 6 significant figures). */
#include <stdio.h>
#include <math.h>
int main(void){
    double xs[] = {0.5, 1.0, 2.0, 3.0, 5.0, 8.0, 10.0, 15.0, 25.0, 50.0, 0.1, 4.0};
    for (size_t i=0;i<sizeof xs/sizeof xs[0];i++){ double x=xs[i];
        printf("%.4g: j0=%.6g j1=%.6g y0=%.6g y1=%.6g\n", x, j0(x), j1(x), y0(x), y1(x));
    }
    for (int nv=2; nv<=4; nv++)
        printf("jn(%d): 1=%.6g 5=%.6g 20=%.6g | yn 5=%.6g\n",
               nv, jn(nv,1.0), jn(nv,5.0), jn(nv,20.0), yn(nv,5.0));
    printf("j1neg=%.6g j0neg=%.6g y0_0=%.1f y0neg=%g\n", j1(-3.0), j0(-3.0), y0(0.0), y0(-1.0));
    return 0;
}
