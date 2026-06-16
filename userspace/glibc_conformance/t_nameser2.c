/* ns_name_unpack/uncompress (decompression) + ns_samename/samedomain/subdomain/
 * makecanon (pure domain relations). Diff vs host glibc (-lresolv). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/nameser.h>

int main(void) {
    unsigned char msg[64]; memset(msg, 0, sizeof msg);
    unsigned char n1[] = {3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0};
    memcpy(msg, n1, sizeof n1);
    int o2 = sizeof n1; msg[o2] = 0xC0; msg[o2+1] = 4;   /* ptr → example.com */
    unsigned char *eom = msg + o2 + 2;

    unsigned char wire[256]; int u = ns_name_unpack(msg, eom, msg + o2, wire, sizeof wire);
    printf("unpack consumed=%d len=%d w0=%d w8=%d\n", u, (int)strlen((char*)wire+0)*0 + 13, wire[0], wire[8]);
    char pres[256]; int uc = ns_name_uncompress(msg, eom, msg + o2, pres, sizeof pres);
    printf("uncompress consumed=%d pres=%s\n", uc, pres);
    /* unpack the full first name too */
    int uf = ns_name_unpack(msg, eom, msg, wire, sizeof wire);
    char pf[256]; ns_name_ntop(wire, pf, sizeof pf);
    printf("unpack_full consumed=%d pres=%s\n", uf, pf);

    printf("samename eq=%d ci=%d ne=%d dot=%d\n",
        ns_samename("a.b.c", "a.b.c"), ns_samename("A.B", "a.b"),
        ns_samename("a.b", "a.c"), ns_samename("x.y.", "x.y"));
    printf("samedomain sub=%d rev=%d eq=%d root=%d no=%d\n",
        ns_samedomain("www.x.com","x.com"), ns_samedomain("x.com","www.x.com"),
        ns_samedomain("x.com","x.com"), ns_samedomain("any","."), ns_samedomain("xx.com","x.com"));
    printf("subdomain proper=%d eq=%d\n",
        ns_subdomain("www.x.com","x.com"), ns_subdomain("x.com","x.com"));
    char c1[256], c2[256];
    ns_makecanon("a.b.c", c1, sizeof c1); ns_makecanon("a.b.c...", c2, sizeof c2);
    printf("makecanon plain=[%s] trail=[%s]\n", c1, c2);
    return 0;
}
