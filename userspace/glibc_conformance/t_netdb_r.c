/* getservbyname_r/getprotobyname_r/getnetbyname_r (+ent_r) deep-copy. vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>

int main(void) {
    char buf[2048];
    struct servent se, *sr = NULL;
    int r = getservbyname_r("http", "tcp", &se, buf, sizeof buf, &sr);
    printf("serv r=%d found=%d port=%d name=%s\n",
           r, sr != NULL, sr ? ntohs(se.s_port) : -1, sr ? se.s_name : "");

    struct protoent pe, *pr = NULL;
    int r2 = getprotobyname_r("tcp", &pe, buf, sizeof buf, &pr);
    printf("proto r=%d found=%d num=%d name=%s\n",
           r2, pr != NULL, pr ? pe.p_proto : -1, pr ? pe.p_name : "");

    /* ERANGE on a tiny buffer */
    char tiny[8];
    struct servent se2, *sr2 = NULL;
    int r3 = getservbyname_r("http", "tcp", &se2, tiny, sizeof tiny, &sr2);
    printf("erange=%d\n", r3 == ERANGE);

    /* enumeration _r: first entry name non-empty */
    struct protoent pe2, *pr2 = NULL;
    setprotoent(1);
    int r4 = getprotoent_r(&pe2, buf, sizeof buf, &pr2);
    printf("protoent r=%d first=%d\n", r4, pr2 != NULL && pe2.p_name[0] != 0);
    endprotoent();

    struct hostent he, *hr = NULL;
    int herr = 0;
    sethostent(1);
    int r5 = gethostent_r(&he, buf, sizeof buf, &hr, &herr);
    printf("hostent r=%d first=%d type=%d\n", r5, hr != NULL && he.h_name[0] != 0,
           hr ? he.h_addrtype : -1);
    endhostent();
    return 0;
}
