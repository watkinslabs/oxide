#include <stdio.h>
#include <math.h>
int main(void){
    printf("remainder=%.4f\n", remainder(10.0,3.0));
    int q; double r = remquo(10.0,3.0,&q); printf("remquo=%.4f,%d\n", r, q);
    printf("nextafter=%.17g\n", nextafter(1.0, 2.0));
    printf("rem2=%.4f remquo2=", remainder(-7.0,4.0));
    double r2 = remquo(-7.0,4.0,&q); printf("%.4f,%d\n", r2, q);
    return 0;
}
