/* wide _l: ctype/case/collate/numeric delegators (C locale). vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>
#include <locale.h>

int main(void) {
    locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    printf("ctype=%d %d %d\n", iswalpha_l(L'A', loc) != 0, iswdigit_l(L'5', loc) != 0, iswspace_l(L' ', loc) != 0);
    printf("case=%d %d\n", towupper_l(L'a', loc) == L'A', towlower_l(L'Z', loc) == L'z');
    wctype_t cl = wctype_l("alpha", loc);
    printf("wctype=%d isw=%d\n", cl != 0, iswctype_l(L'q', cl, loc) != 0);
    printf("coll=%d casecmp=%d\n", wcscoll_l(L"a", L"b", loc) < 0, wcscasecmp_l(L"ABC", L"abc", loc) == 0);
    printf("num=%d %ld %lu\n", wcstod_l(L"3.5", NULL, loc) == 3.5, (long)wcstol_l(L"ff", NULL, 16, loc), (unsigned long)wcstoul_l(L"42", NULL, 10, loc));
    freelocale(loc);
    return 0;
}
