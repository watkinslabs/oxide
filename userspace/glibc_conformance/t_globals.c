/* in6addr_any / in6addr_loopback exported const data. vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

int main(void) {
    struct in6_addr any = IN6ADDR_ANY_INIT;
    struct in6_addr lo = IN6ADDR_LOOPBACK_INIT;
    printf("in6addr_any=%d\n", memcmp(&in6addr_any, &any, sizeof any) == 0);
    printf("in6addr_loopback=%d\n", memcmp(&in6addr_loopback, &lo, sizeof lo) == 0);
    /* spot-check the bytes directly */
    const unsigned char *a = (const unsigned char *)&in6addr_any;
    const unsigned char *l = (const unsigned char *)&in6addr_loopback;
    int any_zero = 1; for (int i = 0; i < 16; i++) any_zero &= (a[i] == 0);
    printf("any_allzero=%d loopback_last1=%d\n", any_zero, l[15] == 1);
    return 0;
}
