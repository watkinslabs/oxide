/* inet6_rth_* (RFC3542 IPv6 routing header type 0) vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(void){
    printf("space: %u %u %u %u\n",
      (unsigned)inet6_rth_space(IPV6_RTHDR_TYPE_0,0),
      (unsigned)inet6_rth_space(IPV6_RTHDR_TYPE_0,1),
      (unsigned)inet6_rth_space(IPV6_RTHDR_TYPE_0,3),
      (unsigned)inet6_rth_space(99,3));
    unsigned char buf[256];
    void *r = inet6_rth_init(buf, sizeof buf, IPV6_RTHDR_TYPE_0, 3);
    printf("init=%d segs=%d\n", r==(void*)buf, inet6_rth_segments(buf));
    struct in6_addr a[3];
    inet_pton(AF_INET6,"2001:db8::1",&a[0]);
    inet_pton(AF_INET6,"2001:db8::2",&a[1]);
    inet_pton(AF_INET6,"2001:db8::3",&a[2]);
    int e1=inet6_rth_add(buf,&a[0]);
    int e2=inet6_rth_add(buf,&a[1]);
    int e3=inet6_rth_add(buf,&a[2]);
    int e4=inet6_rth_add(buf,&a[0]); /* full -> -1 */
    printf("adds=%d,%d,%d,%d hdr=%u,%u,%u,%u\n", e1,e2,e3,e4, buf[0],buf[1],buf[2],buf[3]);
    for(int i=0;i<3;i++){ char s[64]; inet_ntop(AF_INET6, inet6_rth_getaddr(buf,i), s, sizeof s); printf("get[%d]=%s\n", i, s); }
    printf("get_oob=%p\n", (void*)inet6_rth_getaddr(buf,3));
    unsigned char out[256];
    int rv = inet6_rth_reverse(buf, out);
    printf("reverse=%d segleft=%u\n", rv, out[3]);
    for(int i=0;i<3;i++){ char s[64]; inet_ntop(AF_INET6, inet6_rth_getaddr(out,i), s, sizeof s); printf("rev[%d]=%s\n", i, s); }
    /* in-place reverse */
    inet6_rth_reverse(out, out);
    for(int i=0;i<3;i++){ char s[64]; inet_ntop(AF_INET6, inet6_rth_getaddr(out,i), s, sizeof s); printf("rev2[%d]=%s\n", i, s); }
    return 0;
}
