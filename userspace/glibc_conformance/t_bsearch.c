#include <stdio.h>
#include <stdlib.h>
static int cmp(const void *a, const void *b){ return *(const int*)a - *(const int*)b; }
int main(void){
    int v[] = {2,5,8,11,14,17,20,23};
    size_t n = sizeof v / sizeof v[0];
    int keys[] = {2, 14, 23, 1, 13, 24};
    for (size_t i = 0; i < sizeof keys/sizeof keys[0]; i++){
        int *r = bsearch(&keys[i], v, n, sizeof v[0], cmp);
        printf("k=%d -> %s%d\n", keys[i], r?"idx ":"miss", r? (int)(r - v) : -1);
    }
    /* div/ldiv while here */
    div_t d = div(-17, 5); ldiv_t l = ldiv(1000000007L, 13L);
    printf("div q=%d r=%d ldiv q=%ld r=%ld\n", d.quot, d.rem, l.quot, l.rem);
    return 0;
}
