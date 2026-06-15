/* Comprehensive strtol/strtoul family audit vs host glibc: bases, signs,
   prefixes, whitespace, endptr position, overflow clamping + ERANGE. */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

static void L(const char *s, int base){
    char *end; errno = 0;
    long v = strtol(s, &end, base);
    printf("strtol(%s,%d)=%ld off=%ld err=%d\n", s, base, v, (long)(end-s), errno);
}
static void UL(const char *s, int base){
    char *end; errno = 0;
    unsigned long v = strtoul(s, &end, base);
    printf("strtoul(%s,%d)=%lu off=%ld err=%d\n", s, base, v, (long)(end-s), errno);
}
static void LL(const char *s){
    char *end; errno = 0;
    long long v = strtoll(s, &end, 0);
    printf("strtoll(%s)=%lld off=%ld err=%d\n", s, v, (long)(end-s), errno);
}

int main(void){
    L("42", 10); L("  -42xyz", 10); L("+17", 10);
    L("0x1F", 16); L("0x1F", 0); L("0X1f", 0); L("017", 0); L("017", 8);
    L("101", 2); L("z", 36); L("zz", 36); L("HELLO", 36);
    L("", 10); L("  ", 10); L("0x", 16); L("xyz", 10);
    L("2147483648", 10); L("-2147483649", 10);
    L("9223372036854775807", 10);   /* LONG_MAX */
    L("9223372036854775808", 10);   /* overflow -> clamp + ERANGE */
    L("-9223372036854775808", 10);  /* LONG_MIN */
    L("-9223372036854775809", 10);  /* underflow */
    L("0xFFFFFFFFFFFFFFFF", 16);    /* overflow for signed */

    UL("4294967295", 10);
    UL("18446744073709551615", 10);          /* ULONG_MAX */
    UL("18446744073709551616", 10);          /* overflow -> ERANGE */
    UL("-1", 10);                            /* glibc: wraps to ULONG_MAX */
    UL("0xdeadbeef", 0);

    LL("0b1010"); /* base 0: glibc (non-C23) stops at 'b' -> 0, off=1 */
    LL("123456789012345");
    LL("0777");
    return 0;
}
