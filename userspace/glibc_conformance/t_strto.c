#include <stdio.h>
#include <stdlib.h>
int main(void){
    printf("l=%ld ul=%lu\n", strtol("-12345",0,10), strtoul("0xff",0,16));
    printf("base2=%ld atoi=%d\n", strtol("1010",0,2), atoi("987"));
    printf("d=%.4f\n", strtod("3.14159",0));
    char *le;
    long double ld = strtold(" -12345e0rest", &le);
    printf("ld=%d rest=%s\n", ld == -12345.0L, le);
    ld = strtold("0x1.8p+2zz", &le);
    printf("ldhex=%d rest=%s\n", ld == 6.0L, le);
    char *e; long v=strtol("42rest",&e,10); printf("v=%ld rest=%s\n", v, e);
    return 0;
}
