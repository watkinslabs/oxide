#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <inttypes.h>
#include <time.h>
#include <wchar.h>
#include <complex.h>

int main(void){
    /* index / rindex (BSD aliases of strchr / strrchr) */
    const char *s = "a/b/c/d";
    printf("index=%ld rindex=%ld\n", (long)(index(s,'/')-s), (long)(rindex(s,'/')-s));

    /* toascii / isascii / _tolower / _toupper over a byte range */
    int asc=0, lo=0, up=0;
    for (int c = 0x40; c <= 0x60; c++) {
        asc += isascii(c);
        lo  += _tolower(c);
        up  += _toupper(c);
    }
    printf("isascii_sum=%d tolower_sum=%d toupper_sum=%d toascii200=%d\n",
           asc, lo, up, toascii(200));

    /* strtoq / strtouq / wcstoq parse */
    long long q = strtoq("-12345 tail", NULL, 10);
    unsigned long long uq = strtouq("0xFF", NULL, 0);
    long long wq = wcstoq(L"777", NULL, 8);
    printf("q=%lld uq=%llu wq=%lld\n", q, uq, wq);

    /* imaxdiv(17,5) */
    imaxdiv_t id = imaxdiv(17, 5);
    printf("imaxdiv quot=%jd rem=%jd\n", id.quot, id.rem);

    /* mbsnrtowcs / wcsnrtombs round-trip (ASCII; locale-agnostic) */
    const char *mb = "hello";
    const char *mp = mb;
    wchar_t wbuf[16];
    size_t nw = mbsnrtowcs(wbuf, &mp, strlen(mb), 16, NULL);
    const wchar_t *wp = wbuf;
    char obuf[32];
    size_t nb = wcsnrtombs(obuf, &wp, nw, 32, NULL);
    obuf[nb] = 0;
    printf("nw=%zu nb=%zu rt=%s\n", nw, nb, obuf);

    /* strptime("2026-06-15 13:45", "%Y-%m-%d %H:%M", &tm) */
    struct tm tmv;
    memset(&tmv, 0, sizeof tmv);
    strptime("2026-06-15 13:45", "%Y-%m-%d %H:%M", &tmv);
    printf("tm Y=%d m=%d d=%d H=%d M=%d\n",
           tmv.tm_year+1900, tmv.tm_mon+1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min);

    /* wcsftime(L"%Y-%m-%d", tm) */
    wchar_t wf[64];
    wcsftime(wf, 64, L"%Y-%m-%d", &tmv);
    printf("wcsftime=%ls\n", wf);

    /* rpmatch("yes") / rpmatch("no") */
    printf("rpmatch yes=%d no=%d\n", rpmatch("yes"), rpmatch("no"));

    /* strerror_r on a known errno (GNU char*-returning form) */
    char eb[64];
    char *em = strerror_r(2, eb, sizeof eb);
    printf("strerror_r=%s\n", em);

    /* clog10 at a test point */
    double complex z = 3.0 + 4.0*I;
    double complex l = clog10(z);
    printf("clog10=%.12g %.12g\n", creal(l), cimag(l));

    return 0;
}
