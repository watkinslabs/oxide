/* wcwidth/wcswidth over version-stable code points. vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <wchar.h>
#include <locale.h>

int main(void) {
    setlocale(LC_ALL, "C.UTF-8");
    /* stable across glibc versions: ASCII=1, NUL=0, C0/C1 ctrl=-1,
     * combining=0, CJK/Hangul/fullwidth=2 */
    wchar_t pts[] = { 0, 'A', ' ', 0x01, 0x7f, 0x80,
                      0x0301, 0x200B, 0x4E00, 0xAC00, 0xFF01, 0x3000, 0x1F100 };
    for (size_t i = 0; i < sizeof pts / sizeof pts[0]; i++)
        printf("%d ", wcwidth(pts[i]));
    printf("\n");

    printf("hello=%d\n", wcswidth(L"hello", 5));      /* 5 */
    printf("cjk=%d\n", wcswidth(L"一二", 2)); /* 4 (two wide) */
    printf("mixed=%d\n", wcswidth(L"a一b", 3));   /* 1+2+1 = 4 */
    printf("ctrl=%d\n", wcswidth(L"a\tb", 3));        /* -1 (tab non-printable) */
    return 0;
}
