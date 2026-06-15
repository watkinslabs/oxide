/* Comprehensive sscanf conformance audit vs host glibc. Each line prints the
   return value (assignment count) and parsed fields; any mismatch is a bug. */
#include <stdio.h>

int main(void){
    int a, b, c, n;
    long la; long long lla; unsigned u; short sh; char ch;
    double d; float fl;
    char s1[32], s2[32];

    /* ---- integers: base, sign, whitespace ---- */
    a=b=0; n=sscanf("  42 -7", "%d %d", &a, &b);          printf("int1 r=%d a=%d b=%d\n", n,a,b);
    a=0;   n=sscanf("0x1F", "%x", &a);                    printf("hex r=%d a=%d\n", n,a);
    a=0;   n=sscanf("0x1F", "%i", &a);                    printf("i_hex r=%d a=%d\n", n,a);
    a=0;   n=sscanf("017", "%i", &a);                     printf("i_oct r=%d a=%d\n", n,a);
    a=0;   n=sscanf("755", "%o", &a);                     printf("oct r=%d a=%d\n", n,a);
    u=0;   n=sscanf("4294967295", "%u", &u);              printf("u r=%d u=%u\n", n,u);
    a=b=0; n=sscanf("12345", "%2d%3d", &a, &b);           printf("width r=%d a=%d b=%d\n", n,a,b);
    a=-1;  n=sscanf("abc", "%d", &a);                     printf("fail r=%d a=%d\n", n,a);

    /* ---- length modifiers ---- */
    la=0;  n=sscanf("9999999999", "%ld", &la);            printf("ld r=%d la=%ld\n", n,la);
    lla=0; n=sscanf("123456789012345", "%lld", &lla);     printf("lld r=%d lla=%lld\n", n,lla);
    sh=0;  n=sscanf("300", "%hd", &sh);                   printf("hd r=%d sh=%d\n", n,(int)sh);

    /* ---- floats ---- */
    d=0;   n=sscanf("3.14159", "%lf", &d);                printf("lf r=%d d=%.5f\n", n,d);
    fl=0;  n=sscanf("2.5e3", "%f", &fl);                  printf("f r=%d fl=%.1f\n", n,fl);
    d=0;   n=sscanf("-0.001", "%lf", &d);                 printf("fneg r=%d d=%.4f\n", n,d);

    /* ---- strings / chars ---- */
    s1[0]=0; n=sscanf("  hello world", "%s", s1);         printf("str r=%d s=%s\n", n,s1);
    s1[0]=s2[0]=0; n=sscanf("foo bar", "%s %s", s1, s2);  printf("2str r=%d a=%s b=%s\n", n,s1,s2);
    ch=0;  n=sscanf("xyz", "%c", &ch);                    printf("ch r=%d c=%c\n", n,ch);
    s1[0]=0; n=sscanf("abcdefgh", "%4s", s1);             printf("wstr r=%d s=%s\n", n,s1);

    /* ---- scanset ---- */
    s1[0]=0; n=sscanf("hello,rest", "%[^,]", s1);         printf("set r=%d s=%s\n", n,s1);
    s1[0]=0; n=sscanf("12.34xy", "%[0-9.]", s1);          printf("setrange r=%d s=%s\n", n,s1);

    /* ---- suppression + literal matching ---- */
    a=b=0; n=sscanf("10:20", "%d:%d", &a, &b);            printf("colon r=%d a=%d b=%d\n", n,a,b);
    a=0;   n=sscanf("skip 99", "%*s %d", &a);             printf("supp r=%d a=%d\n", n,a);

    /* ---- %n (chars consumed so far; not an assignment) ---- */
    a=0; n=sscanf("12345 end", "%d%n", &a, &c);           printf("pctn r=%d a=%d n=%d\n", n,a,c);

    /* ---- EOF / empty ---- */
    a=-1; n=sscanf("", "%d", &a);                         printf("eof r=%d\n", n);
    return 0;
}
