#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
int main(void){
    printf("llabs=%lld\n", llabs(-9999999999LL));
    lldiv_t r = lldiv(-100LL, 7LL); printf("lldiv q=%lld rem=%lld\n", r.quot, r.rem);
    printf("imaxabs=%jd\n", imaxabs((intmax_t)-42));
    return 0;
}
