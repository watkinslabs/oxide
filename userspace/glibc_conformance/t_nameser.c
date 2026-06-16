/* libresolv ns_* wire helpers: ns_get/put16/32, ns_name_ntop/pton/skip. Pure
 * RFC1035 codec — diff vs host glibc (-lresolv). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/nameser.h>

static void rt(const char *lbl, const unsigned char *wire, int wlen) {
    char pres[1024];
    int r = ns_name_ntop(wire, pres, sizeof pres);
    unsigned char back[1024];
    int p = (r < 0) ? -99 : ns_name_pton(pres, back, sizeof back);
    int m = (p < 0) ? 0 : (memcmp(back, wire, wlen) == 0);
    printf("%s: ntop=%d pres=[%s] pton=%d rt=%d\n", lbl, r, r<0?"":pres, p, m);
}

int main(void) {
    unsigned char b[8];
    ns_put16(0xBEEF, b); ns_put32(0xDEADBEEFu, b+2);
    printf("get16=%x get32=%lx\n", (unsigned)ns_get16(b), (unsigned long)ns_get32(b+2));

    unsigned char root[] = {0};
    unsigned char w1[]   = {3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0};
    unsigned char dot[]  = {3,'a','.','b',2,'c','d',0};
    unsigned char np[]   = {2,1,255,0};            /* \001\255 */
    unsigned char specs[]= {4,'a','@','$',';',0};  /* escaped specials */
    rt("root", root, 1);
    rt("www",  w1, sizeof w1);
    rt("dot",  dot, sizeof dot);
    rt("np",   np, sizeof np);
    rt("specs", specs, sizeof specs);

    /* fully-qualified presentation (trailing dot) ⇒ pton returns 1 */
    unsigned char fq[256];
    printf("fqdn pton=%d\n", ns_name_pton("a.b.", fq, sizeof fq));

    /* ns_name_skip over a message with a name + trailing data */
    unsigned char msg[] = {1,'x',0, 0xAA,0xBB};
    const unsigned char *cp = msg, *eom = msg + sizeof msg;
    int s = ns_name_skip(&cp, eom);
    printf("skip=%d adv=%ld\n", s, (long)(cp - msg));

    /* ns_name_skip across a compression pointer */
    unsigned char msg2[] = {0xC0,0x0C, 0,0};
    const unsigned char *cp2 = msg2, *eom2 = msg2 + sizeof msg2;
    int s2 = ns_name_skip(&cp2, eom2);
    printf("skip_ptr=%d adv=%ld\n", s2, (long)(cp2 - msg2));
    return 0;
}
