#include <stdio.h>
#include <stdlib.h>
int main(void){
    printf("l=%ld ul=%lu\n", strtol("-12345",0,10), strtoul("0xff",0,16));
    printf("base2=%ld atoi=%d\n", strtol("1010",0,2), atoi("987"));
    printf("d=%.4f\n", strtod("3.14159",0));
    char *e; long v=strtol("42rest",&e,10); printf("v=%ld rest=%s\n", v, e);
    return 0;
}
