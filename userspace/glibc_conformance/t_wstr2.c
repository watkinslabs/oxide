#define _GNU_SOURCE
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
static int sgn(int x){ return x<0?-1:x>0?1:0; }
int main(void){
    wchar_t buf[16] = L"foo";
    wcscat(buf, L"bar");
    wcsncat(buf, L"bazzz", 3);
    printf("cat=%ls len=%zu\n", buf, wcslen(buf));
    wchar_t cp[8];
    wcsncpy(cp, L"hi", 8);
    printf("ncpy0=%d ncpy_pad=%d\n", cp[2], cp[3]);
    const wchar_t *s = L"abcXdefX";
    printf("rchr_off=%ld\n", (long)(wcsrchr(s, L'X') - s));
    printf("spn=%zu cspn=%zu\n", wcsspn(L"aabbc", L"ab"), wcscspn(L"abcd", L"cz"));
    const wchar_t *hp = L"hello";
    printf("pbrk_off=%ld str_off=%ld\n", (long)(wcspbrk(hp, L"lo") - hp), (long)(wcsstr(s, L"def") - s));
    wchar_t a[] = {1,2,3,4}, b[4];
    wmemcpy(b, a, 4);
    printf("wmemcpy=%d wmemcmp=%d\n", b[2], sgn(wmemcmp(a, (wchar_t[]){1,2,9,4}, 4)));
    printf("wmemchr_off=%ld\n", (long)(wmemchr(a, 3, 4) - a));
    wchar_t *d = wcsdup(L"dup");
    printf("dup=%ls\n", d);
    free(d);

    /* wcpcpy/wcpncpy/wcschrnul/wcsnlen/wcscoll/wcsxfrm */
    wchar_t cb[16];
    long ce = wcpcpy(cb, L"abc") - cb;          /* returns &terminator */
    printf("wcpcpy end=%ld s=%ls\n", ce, cb);
    wchar_t pb[8]; long pe2 = wcpncpy(pb, L"hi", 5) - pb;
    printf("wcpncpy end=%ld pad=%d\n", pe2, pb[3]);
    const wchar_t *cn = L"a.b.c";
    printf("chrnul_hit=%ld chrnul_miss=%ld\n", wcschrnul(cn, L'.') - cn, wcschrnul(cn, L'z') - cn);
    printf("nlen=%zu nlen_cap=%zu\n", wcsnlen(L"hello", 9), wcsnlen(L"hello", 3));
    printf("coll=%d\n", wcscoll(L"abc", L"abd") < 0);
    wchar_t xb[16]; size_t xn = wcsxfrm(xb, L"xfrm", sizeof xb/sizeof xb[0]);
    printf("xfrm n=%zu s=%ls\n", xn, xb);
    return 0;
}
