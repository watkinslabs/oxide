#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <unistd.h>
int main(void){
    setlocale(LC_ALL, "C.UTF-8");
    const char *path = "/tmp/oxide_widestdio.txt";

    /* swprintf / swscanf round-trip into a wchar_t buffer (whitespace-delimited
       so %ls stops at the space) */
    wchar_t wb[64];
    int n = swprintf(wb, 64, L"%ls %d %lc", L"abc", 42, (wint_t)L'Z');
    int rd = 0; wchar_t rs[16] = {0}; wchar_t rc = 0;
    int got = swscanf(wb, L"%ls %d %lc", rs, &rd, &rc);
    printf("swprintf n=%d swscanf got=%d rd=%d rc=%lc rs=%ls\n", n, got, rd, rc, rs);

    /* write a tmpfile with wide ops, set + check orientation */
    FILE *f = fopen(path, "w");
    if(!f){ printf("fopen-w-fail\n"); return 1; }
    int o0 = fwide(f, 0);
    fputwc(L'H', f); fputwc(L'i', f); fputwc(L'\n', f);
    fputws(L"second line\n", f);
    fwprintf(f, L"num=%d str=%ls end\n", 7, L"wide");
    int o1 = fwide(f, 0);
    fclose(f);

    /* read it back with fgetwc / fgetws / fwscanf */
    f = fopen(path, "r");
    if(!f){ printf("fopen-r-fail\n"); return 1; }
    wint_t c0 = fgetwc(f);
    wint_t c1 = fgetwc(f);
    wint_t c2 = fgetwc(f);
    wchar_t line[64];
    fgetws(line, 64, f);
    line[wcscspn(line, L"\n")] = 0;
    int num; wchar_t sval[16];
    int sc = fwscanf(f, L"num=%d str=%ls", &num, sval);
    fclose(f);

    printf("orient0=%d orient1=%d\n", o0>0?1:(o0<0?-1:0), o1>0?1:(o1<0?-1:0));
    printf("c0=%lc c1=%lc nl=%d line=%ls num=%d sval=%ls sc=%d\n",
           (wint_t)c0, (wint_t)c1, c2==(wint_t)L'\n', line, num, sval, sc);

    /* ungetwc */
    f = fopen(path, "r");
    wint_t g = fgetwc(f);
    ungetwc(g, f);
    wint_t g2 = fgetwc(f);
    printf("unget g=%lc g2=%lc same=%d\n", (wint_t)g, (wint_t)g2, g==g2);
    fclose(f);

    unlink(path);
    return 0;
}
