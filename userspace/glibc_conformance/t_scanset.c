#include <stdio.h>
int main(void){
    char a[32], b[32];
    int n;
    /* read up to a comma, then skip comma, then rest */
    n = sscanf("hello,world", "%[^,],%[a-z]", a, b);
    printf("n=%d a=%s b=%s\n", n, a, b);
    /* positive set: digits only */
    char num[16]; int got = sscanf("12345abc", "%[0-9]", num);
    printf("got=%d num=%s\n", got, num);
    /* literal ] as first set member */
    char br[8]; sscanf("]]]x", "%[]]", br);
    printf("br=%s\n", br);
    /* width limit + suppression */
    char w[8]; int r = sscanf("aaaabbbb", "%4[a]%*[a]%[b]", w, a);
    printf("r=%d w=%s a=%s\n", r, w, a);
    /* negated set stops at newline */
    char line[32]; sscanf("first line\nsecond", "%[^\n]", line);
    printf("line=%s\n", line);
    /* no match -> conversion fails */
    char z[8]; int rr = sscanf("xyz", "%[0-9]", z);
    printf("nomatch=%d\n", rr);
    return 0;
}
