/* /etc/rpc DB: getrpcbyname/getrpcbynumber/getrpcent_r. vs host glibc. */
#define _GNU_SOURCE
#include <netdb.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    struct rpcent *r = getrpcbyname("portmapper");
    printf("byname=%d num=%d\n", r != NULL, r ? r->r_number : -1);
    struct rpcent *n = getrpcbynumber(100000);
    printf("bynum=%d name=%s\n", n != NULL, n ? (char*)n->r_name : "");

    char buf[2048]; struct rpcent e, *res = NULL;
    int rr = getrpcbyname_r("portmapper", &e, buf, sizeof buf, &res);
    printf("byname_r=%d found=%d num=%d\n", rr, res != NULL, res ? e.r_number : -1);

    /* enumeration _r: first entry has a name */
    setrpcent(1);
    struct rpcent e2, *res2 = NULL;
    int r2 = getrpcent_r(&e2, buf, sizeof buf, &res2);
    printf("ent_r=%d first=%d\n", r2, res2 != NULL && e2.r_name[0] != 0);
    endrpcent();
    return 0;
}
