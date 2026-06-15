#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
int main(void){
    char b[32]; char *e = stpcpy(b, "hello"); printf("stpcpy_off=%ld s=%s\n", e-b, b);
    char d[32]; void *p = mempcpy(d, "abcXYZ", 6); d[6]=0; printf("mempcpy_off=%ld s=%s\n", (char*)p-d, d);
    char *cn = strchrnul("foo", 'X'); printf("chrnul_at_nul=%d\n", *cn==0);
    char s[]="a:b:c"; char *str=s, *tok; int i=0;
    while((tok=strsep(&str,":"))) printf("sep%d=%s ", i++, tok);
    printf("\n");
    return 0;
}
