#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
int main(void){
    const char *h = "The Quick Brown Fox";
    char *r = strcasestr(h, "brown");
    printf("off=%ld match=%.5s\n", r ? (long)(r - h) : -1L, r ? r : "");
    printf("miss=%d\n", strcasestr(h, "zebra") == NULL);
    char buf[] = "abcXdef";
    char *p = rawmemchr(buf, 'X');
    printf("raw_off=%ld\n", (long)(p - buf));
    return 0;
}
