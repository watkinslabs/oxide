/* ether_aton/ntoa (deterministic) + arc4random (property checks). vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ether.h>

int main(void) {
    struct ether_addr a;
    ether_aton_r("01:23:45:ab:cd:ef", &a);
    printf("aton=%02x%02x%02x%02x%02x%02x\n",
           a.ether_addr_octet[0], a.ether_addr_octet[1], a.ether_addr_octet[2],
           a.ether_addr_octet[3], a.ether_addr_octet[4], a.ether_addr_octet[5]);
    char buf[32];
    ether_ntoa_r(&a, buf);
    printf("ntoa=%s\n", buf);
    /* round-trip via the static-buffer forms */
    struct ether_addr *p = ether_aton("de:ad:be:ef:00:01");
    printf("ntoa2=%s\n", ether_ntoa(p));
    printf("bad=%d\n", ether_aton_r("xy:zz", &a) == NULL);

    /* arc4random: only deterministic properties (values are random) */
    printf("uniform1=%d\n", arc4random_uniform(1));        /* always 0 */
    printf("uniform_lt=%d\n", arc4random_uniform(100) < 100);
    unsigned char z[16] = {0}; arc4random_buf(z, 0);       /* no-op */
    int allzero = 1; for (int i = 0; i < 16; i++) allzero &= (z[i] == 0);
    printf("buf0_noop=%d\n", allzero);
    return 0;
}
