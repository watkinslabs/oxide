/* ns_initparse/ns_parserr/ns_skiprr/ns_msg_getflag — DNS message parser. Diff
 * vs host glibc (-lresolv). The ns_msg/ns_rr structs come from the host header;
 * our codec writes them via the matching 80/1048-byte ABI. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/nameser.h>

int main(void) {
    /* response: 1 question (example.com A), 2 answers (A 1.2.3.4, A 5.6.7.8) */
    unsigned char m[] = {
        0x12,0x34, 0x81,0x80, 0,1, 0,2, 0,0, 0,0,
        7,'e','x','a','m','p','l','e',3,'c','o','m',0, 0,1, 0,1,
        0xC0,0x0C, 0,1, 0,1, 0,0,0x0E,0x10, 0,4, 1,2,3,4,
        0xC0,0x0C, 0,1, 0,1, 0,0,0x00,0x3C, 0,4, 5,6,7,8
    };
    ns_msg h;
    int r = ns_initparse(m, sizeof m, &h);
    printf("init r=%d id=%d qd=%d an=%d ns=%d ar=%d\n", r, ns_msg_id(h),
        ns_msg_count(h,ns_s_qd), ns_msg_count(h,ns_s_an),
        ns_msg_count(h,ns_s_ns), ns_msg_count(h,ns_s_ar));
    printf("flags qr=%d op=%d aa=%d tc=%d rd=%d ra=%d rcode=%d\n",
        ns_msg_getflag(h,ns_f_qr), ns_msg_getflag(h,ns_f_opcode), ns_msg_getflag(h,ns_f_aa),
        ns_msg_getflag(h,ns_f_tc), ns_msg_getflag(h,ns_f_rd), ns_msg_getflag(h,ns_f_ra),
        ns_msg_getflag(h,ns_f_rcode));

    /* question */
    ns_rr q;
    int qr = ns_parserr(&h, ns_s_qd, 0, &q);
    printf("q r=%d name=%s type=%d class=%d\n", qr, ns_rr_name(q), ns_rr_type(q), ns_rr_class(q));

    /* both answers */
    for (int i = 0; i < 2; i++) {
        ns_rr rr;
        int pr = ns_parserr(&h, ns_s_an, i, &rr);
        const unsigned char *rd = ns_rr_rdata(rr);
        printf("an%d r=%d name=%s type=%d class=%d ttl=%u rdlen=%d ip=%d.%d.%d.%d\n",
            i, pr, ns_rr_name(rr), ns_rr_type(rr), ns_rr_class(rr), ns_rr_ttl(rr),
            ns_rr_rdlen(rr), rd[0], rd[1], rd[2], rd[3]);
    }
    /* out-of-range rrnum ⇒ error */
    ns_rr bad;
    printf("oob r=%d\n", ns_parserr(&h, ns_s_an, 5, &bad));
    return 0;
}
