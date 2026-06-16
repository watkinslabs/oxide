/* ether_line / ether_hostton / ether_ntohost. vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>

int main(void) {
    struct ether_addr a;
    char host[256];
    int r = ether_line("01:02:03:04:05:06 myhost", &a, host);
    printf("line=%d mac=%02x%02x%02x%02x%02x%02x host=%s\n",
           r, a.ether_addr_octet[0],a.ether_addr_octet[1],a.ether_addr_octet[2],
           a.ether_addr_octet[3],a.ether_addr_octet[4],a.ether_addr_octet[5], host);
    printf("line_comment=%d\n", ether_line("# comment", &a, host) != 0);
    /* /etc/ethers absent → not found on both libs */
    printf("hostton=%d\n", ether_hostton("no_such_host_xyz", &a) != 0);
    struct ether_addr q = {{0xde,0xad,0xbe,0xef,0,1}};
    printf("ntohost=%d\n", ether_ntohost(host, &q) != 0);
    return 0;
}
