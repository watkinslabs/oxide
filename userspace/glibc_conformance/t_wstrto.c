/* wide numeric/string conversions vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <wchar.h>
int main(void){
    wchar_t *end;
    long l = wcstol(L"  -1234xyz", &end, 10);
    printf("wcstol=%ld rest=%ls\n", l, end);
    printf("hex=%ld oct=%ld u=%lu ll=%lld\n",
           wcstol(L"0x1F", NULL, 16), wcstol(L"017", NULL, 0),
           wcstoul(L"4294967295", NULL, 10), wcstoll(L"9999999999", NULL, 10));
    double d = wcstod(L"3.14159e2zz", &end);
    printf("wcstod=%.5f rest=%ls\n", d, end);
    printf("wcstof=%.3f\n", wcstof(L"-0.5", NULL));
    long double ld = wcstold(L" -12345e0tail", &end);
    printf("wcstold=%d rest=%ls\n", ld == -12345.0L, end);
    ld = wcstold(L"0x1.8p+2zz", &end);
    printf("wcstoldhex=%d rest=%ls\n", ld == 6.0L, end);

    printf("casecmp=%d ncase=%d\n", wcscasecmp(L"Hello", L"hello"), wcsncasecmp(L"ABCx", L"abcY", 3));

    wchar_t s[] = L"a,bb,,ccc", *sv;
    printf("tok:");
    for (wchar_t *t = wcstok(s, L",", &sv); t; t = wcstok(NULL, L",", &sv)) printf(" %ls", t);
    printf("\n");

    printf("wcswcs=%ls\n", wcswcs(L"hello world", L"wor"));
    wchar_t dst[8]; wchar_t *e2 = wmempcpy(dst, L"abcd", 4);
    printf("wmempcpy end=%ld d0=%lc\n", (long)(e2 - dst), dst[0]);
    return 0;
}
