/* float-variant + logb/ilogb math vs host glibc (bit-exact via f64 cores). */
#define _GNU_SOURCE
#include <stdio.h>
#include <math.h>
int main(void){
    float xs[] = {0.0f, -0.0f, 2.5f, -2.5f, 3.5f, 100000.1f, 0.0001f, -7.25f, 1.0f/3.0f};
    for (size_t i=0;i<sizeof xs/sizeof xs[0];i++){ float x=xs[i];
        printf("%.9g: ceilf=%.9g floorf=%.9g truncf=%.9g roundf=%.9g rintf=%.9g\n",
               x, ceilf(x), floorf(x), truncf(x), roundf(x), rintf(x));
    }
    printf("fmodf=%.9g remainderf=%.9g fmaxf=%.9g fminf=%.9g\n",
           fmodf(7.5f,2.0f), remainderf(7.5f,2.0f), fmaxf(1.5f,2.5f), fminf(1.5f,2.5f));
    printf("nextafterf=%.9g na2=%.9g ldexpf=%.9g scalbnf=%.9g\n",
           nextafterf(1.0f,2.0f), nextafterf(1.0f,0.0f), ldexpf(1.5f,3), scalbnf(1.5f,-2));
    int e; float m = frexpf(12.0f,&e); float ip; float fp = modff(-3.75f,&ip);
    printf("frexpf=%.9g,%d modff=%.9g,%.9g\n", m, e, fp, ip);
    printf("logbf=%.9g ilogbf=%d logb=%.9g ilogb=%d scalbln=%.9g\n",
           logbf(8.0f), ilogbf(8.0f), logb(1024.0), ilogb(1024.0), scalbln(1.0, 5));
    printf("ilogb0=%d logb0=%.1f drem=%.9g\n", ilogb(0.0), logb(0.0), drem(7.5,2.0));
    return 0;
}
