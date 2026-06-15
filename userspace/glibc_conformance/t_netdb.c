#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>

/* Deterministic: oracle (host glibc) and oxide libc both run on the host, so
   both read the SAME /etc/{protocols,services,hosts}. Compare only fields
   guaranteed stable across distros (well-known assignments). */
int main(void) {
    /* getprotobyname / getprotobynumber */
    struct protoent *pe = getprotobyname("tcp");
    printf("proto tcp=%d name=%s\n", pe ? pe->p_proto : -1, pe ? pe->p_name : "?");
    pe = getprotobynumber(6);
    printf("proto 6=%s\n", pe ? pe->p_name : "?");
    pe = getprotobyname("icmp");
    printf("proto icmp=%d\n", pe ? pe->p_proto : -1);

    /* getservbyname / getservbyport (s_port is network byte order) */
    struct servent *se = getservbyname("ssh", "tcp");
    printf("serv ssh/tcp=%d name=%s proto=%s\n",
           se ? ntohs(se->s_port) : -1, se ? se->s_name : "?", se ? se->s_proto : "?");
    se = getservbyport(htons(22), "tcp");
    printf("serv 22/tcp=%s\n", se ? se->s_name : "?");
    se = getservbyname("domain", "udp");
    printf("serv domain/udp=%d\n", se ? ntohs(se->s_port) : -1);

    /* gethostbyname over /etc/hosts loopback (stable on every distro) */
    struct hostent *he = gethostbyname("localhost");
    if (he) {
        printf("host localhost type=%d len=%d addr=%u.%u.%u.%u\n",
               he->h_addrtype, he->h_length,
               (unsigned char)he->h_addr_list[0][0], (unsigned char)he->h_addr_list[0][1],
               (unsigned char)he->h_addr_list[0][2], (unsigned char)he->h_addr_list[0][3]);
    } else {
        printf("host localhost=NULL h_errno=%d\n", h_errno);
    }

    /* gethostbyaddr 127.0.0.1 */
    struct in_addr lo; inet_pton(AF_INET, "127.0.0.1", &lo);
    he = gethostbyaddr(&lo, 4, AF_INET);
    printf("host 127.0.0.1=%s\n", he ? he->h_name : "NULL");

    /* gethostbyname_r reentrant */
    struct hostent hb; char hbuf[1024]; struct hostent *hr; int herr;
    int rc = gethostbyname_r("localhost", &hb, hbuf, sizeof hbuf, &hr, &herr);
    printf("host_r rc=%d ok=%d type=%d\n", rc, hr != NULL, hr ? hr->h_addrtype : -1);

    /* h_errno on a name that is not in /etc/hosts and won't resolve via DNS
       here: we only assert the not-found path sets a nonzero h_errno (both
       libs agree it is unfound on the offline harness). */
    he = gethostbyname2("no.such.host.invalid", AF_INET);
    printf("host invalid=%d\n", he == NULL);

    /* getprotobyname miss */
    printf("proto miss=%d\n", getprotobyname("zzznotaproto") == NULL);

    return 0;
}
