#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
int main(void){
    char d[8];
    printf("lcpy_ret=%zu d=%s\n", strlcpy(d, "hello", sizeof d), d);
    char s[4];
    printf("lcpy_trunc_ret=%zu s=%s\n", strlcpy(s, "abcdef", sizeof s), s);
    char c[8] = "ab";
    printf("lcat_ret=%zu c=%s\n", strlcat(c, "cd", sizeof c), c);
    char t[5] = "abc";
    printf("lcat_trunc_ret=%zu t=%s\n", strlcat(t, "xyz", sizeof t), t);
    char z[6] = "secret";
    explicit_bzero(z, 5);
    printf("bzero=%d%d%d%d%d last=%d\n", z[0], z[1], z[2], z[3], z[4], z[5]);
    return 0;
}
