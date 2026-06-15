#include <stdio.h>
#include <stdlib.h>
int main(void){
    printf("abs=%d labs=%ld\n", abs(-7), labs(-123456789L));
    div_t d = div(17,5); printf("div q=%d r=%d\n", d.quot, d.rem);
    ldiv_t l = ldiv(-17,5); printf("ldiv q=%ld r=%ld\n", l.quot, l.rem);
    return 0;
}
