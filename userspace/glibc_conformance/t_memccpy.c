#include <stdio.h>
#include <string.h>
int main(void){
    char dst[16];
    memset(dst, '.', sizeof dst);
    char *p = memccpy(dst, "abc:def", ':', sizeof dst);
    printf("found_off=%ld dst=%.7s\n", p ? (long)(p - dst) : -1L, dst);
    memset(dst, '.', sizeof dst);
    char *q = memccpy(dst, "abcdef", ':', 4);
    printf("absent=%d copied=%.4s\n", q == NULL, dst);
    return 0;
}
