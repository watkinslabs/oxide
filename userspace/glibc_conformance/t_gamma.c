/* tgamma/lgamma vs host glibc at %.12g (Lanczos over our pow/exp/log → tens of
   ULP, invisible at 12 significant figures). */
#include <stdio.h>
#include <math.h>
int main(void){
    double xs[] = {0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 0.1, 0.25, 0.75,
                   6.0, 10.0, -0.5, -1.5, -2.5};
    for (size_t i=0;i<sizeof xs/sizeof xs[0];i++)
        printf("g(%.4g) tgamma=%.12g lgamma=%.12g\n", xs[i], tgamma(xs[i]), lgamma(xs[i]));
    printf("tgammaf=%.6g lgammaf=%.6g\n", tgammaf(4.0f), lgammaf(10.0f));
    int sg = 0;
    printf("tgammal=%.6g lgammal=%.6g\n", (double)tgammal(5.0L), (double)lgammal(10.0L));
    long double lr = lgammal_r(4.0L, &sg);
    printf("lgammal_r=%.6g sign=%d gammal=%.6g\n", (double)lr, sg, (double)gammal(4.0L));
    /* poles / specials */
    printf("g0=%.1f gneg1=%.4g lg0=%.1f lg1=%.4g\n",
           tgamma(0.0), tgamma(-1.0), lgamma(0.0), lgamma(1.0));
    return 0;
}
