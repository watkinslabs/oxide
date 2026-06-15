/* Exact / decomposition math audit vs host glibc (no rounding tolerance):
   rounding, sign, decomposition, fmod/remainder, min/max, ldexp/frexp/modf,
   nextafter — all must be bit-identical. */
#include <stdio.h>
#include <math.h>
#include <float.h>

static double xs[] = {0.0, -0.0, 1.0, -1.0, 2.5, -2.5, 3.5, -3.5, 0.49999999999999994,
                      2.4, -2.4, 100000.1, -0.0001, 1e300, 1e-300, 123.456, -123.456};

int main(void){
    size_t n = sizeof xs/sizeof xs[0];
    for (size_t i=0;i<n;i++){ double x=xs[i];
        printf("r %.17g: ceil=%.17g floor=%.17g trunc=%.17g round=%.17g rint=%.17g nbi=%.17g\n",
               x, ceil(x), floor(x), trunc(x), round(x), rint(x), nearbyint(x));
    }
    for (size_t i=0;i<n;i++){ double x=xs[i];
        printf("s %.17g: fabs=%.17g signbit=%d copysign=%.17g\n", x, fabs(x), !!signbit(x), copysign(3.0, x));
    }
    double pairs[][2] = {{7.5,2.0},{-7.5,2.0},{7.5,-2.0},{5.3,5.3},{1.0,0.0},{10.0,3.0},{-10.0,3.0}};
    for (size_t i=0;i<7;i++){ double a=pairs[i][0],b=pairs[i][1];
        printf("m %.17g,%.17g: fmod=%.17g remainder=%.17g fmax=%.17g fmin=%.17g fdim=%.17g hypot=%.17g\n",
               a,b, fmod(a,b), remainder(a,b), fmax(a,b), fmin(a,b), fdim(a,b), hypot(a,b));
    }
    /* fma exactness */
    printf("fma=%.17g\n", fma(0.1, 0.2, 0.3));
    /* ldexp / scalbn / frexp / modf */
    for (size_t i=0;i<n;i++){ double x=xs[i];
        int e; double m = frexp(x, &e); double ip; double fp = modf(x, &ip);
        printf("d %.17g: ldexp=%.17g scalbn=%.17g frexp=%.17g,%d modf=%.17g,%.17g\n",
               x, ldexp(x,3), scalbn(x,-2), m, e, fp, ip);
    }
    /* nextafter directions */
    printf("na1=%.17g na2=%.17g na3=%.17g\n", nextafter(1.0, 2.0), nextafter(1.0, 0.0), nextafter(0.0, 1.0));
    printf("inf: ceil=%.17g fabs=%.17g fmod=%.17g signbit=%d\n", ceil(INFINITY), fabs(-INFINITY), fmod(INFINITY,1.0), !!signbit(-INFINITY));
    return 0;
}
