#include <stdio.h>
int main(void){
    int a,b; char s[32]; double d;
    int n = sscanf("42 99 hello 3.14", "%d %d %s %lf", &a, &b, s, &d);
    printf("n=%d a=%d b=%d s=%s d=%.2f\n", n, a, b, s, d);
    unsigned x; sscanf("0xFF", "%x", &x); printf("hex=%u\n", x);
    return 0;
}
