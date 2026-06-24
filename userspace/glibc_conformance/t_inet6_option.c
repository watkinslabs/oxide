/* inet6_option_* (obsolete RFC2292 API) vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

static void dump(const unsigned char *b, int n){
    printf("buf:");
    for(int i=0;i<n;i++) printf(" %02x", b[i]);
    printf("\n");
}

int main(void){
    printf("space: %d %d %d %d\n",
           inet6_option_space(0), inet6_option_space(4),
           inet6_option_space(8), inet6_option_space(16));

    unsigned char buf[96];
    memset(buf, 0xee, sizeof buf);
    struct cmsghdr *c = 0;
    printf("init_bad=%d\n", inet6_option_init(buf, &c, IPPROTO_HOPOPTS));
    int r = inet6_option_init(buf, &c, IPV6_HOPOPTS);
    printf("init r=%d len=%zu level=%d type=%d\n", r, (size_t)c->cmsg_len, c->cmsg_level, c->cmsg_type);

    unsigned char opt1[6] = {0x11,4,0xaa,0xbb,0xcc,0xdd};
    unsigned char opt2[4] = {0x22,2,0x55,0x66};
    unsigned char opt3[3] = {0x44,1,0x99};
    r = inet6_option_append(c,opt1,4,2);
    printf("append1=%d len=%zu\n", r, (size_t)c->cmsg_len);
    r = inet6_option_append(c,opt2,2,2);
    printf("append2=%d len=%zu\n", r, (size_t)c->cmsg_len);
    unsigned char *out = inet6_option_alloc(c,4,4,2);
    printf("alloc off=%ld len=%zu\n", out ? (long)(out-buf) : -1L, (size_t)c->cmsg_len);
    if(out){ out[0]=0x33; out[1]=4; out[2]=0xde; out[3]=0xad; out[4]=0xbe; out[5]=0xef; }
    r = inet6_option_append(c,opt3,1,2);
    printf("append3=%d len=%zu\n", r, (size_t)c->cmsg_len);
    dump(buf, (int)c->cmsg_len);

    unsigned char *p = 0;
    int idx = 0;
    while(inet6_option_next(c, &p) == 0)
        printf("next%d off=%ld type=%u len=%u\n", idx++, (long)(p-buf), p[0], p[0] == 0 ? 0 : p[1]);
    printf("next_end=%d\n", inet6_option_next(c, &p));
    p = 0; r = inet6_option_find(c,&p,0x22);
    printf("find22=%d off=%ld len=%u\n", r, p ? (long)(p-buf) : -1L, p ? p[1] : 0);
    p = 0; r = inet6_option_find(c,&p,0x33);
    printf("find33=%d off=%ld len=%u\n", r, p ? (long)(p-buf) : -1L, p ? p[1] : 0);
    p = 0; r = inet6_option_find(c,&p,0x99);
    printf("find99=%d off=%ld\n", r, p ? (long)(p-buf) : -1L);
    return 0;
}
