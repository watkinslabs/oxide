#include <stdio.h>
int main(void){
    char b[128];
    int n = snprintf(b, sizeof b, "%d-%s-%.2f", 7, "mid", 1.5);
    printf("n=%d s=%s\n", n, b);
    n = snprintf(b, 4, "%s", "truncateme"); printf("trunc_n=%d s=%s\n", n, b);
    snprintf(b, sizeof b, "%3d|%-3d|%+d|% d", 5, 5, 5, 5); printf("flags=%s\n", b);
    snprintf(b, sizeof b, "%#x %#o", 255, 64); printf("alt=%s\n", b);
    return 0;
}
