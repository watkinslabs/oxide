/* mbrtoc32 / c32rtomb (UTF-8 <-> UTF-32) in C.UTF-8. vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <uchar.h>
#include <string.h>
#include <locale.h>

int main(void) {
    setlocale(LC_ALL, "C.UTF-8");
    mbstate_t ps; memset(&ps, 0, sizeof ps);
    char32_t c = 0;
    /* "€" = U+20AC = E2 82 AC (3 bytes) */
    const char *euro = "\xE2\x82\xAC";
    size_t r = mbrtoc32(&c, euro, 4, &ps);
    printf("mbrtoc32 len=%zu cp=%u\n", r, (unsigned)c);

    /* ASCII */
    memset(&ps, 0, sizeof ps);
    size_t r2 = mbrtoc32(&c, "A", 1, &ps);
    printf("ascii len=%zu cp=%u\n", r2, (unsigned)c);

    /* encode U+1F600 (emoji) back to UTF-8 */
    memset(&ps, 0, sizeof ps);
    char buf[8] = {0};
    size_t e = c32rtomb(buf, 0x1F600, &ps);
    printf("c32rtomb len=%zu b0=%02x b3=%02x\n", e, (unsigned char)buf[0], (unsigned char)buf[3]);

    /* round-trip euro */
    memset(&ps, 0, sizeof ps);
    char rt[8] = {0};
    size_t e2 = c32rtomb(rt, 0x20AC, &ps);
    printf("roundtrip=%d len=%zu\n", memcmp(rt, euro, 3) == 0, e2);
    return 0;
}
