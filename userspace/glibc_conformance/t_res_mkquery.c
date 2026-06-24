/* res_mkquery/res_nmkquery packet builder vs host glibc. The first two bytes
 * are a resolver-generated ID, so print them masked. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <resolv.h>
#include <arpa/nameser.h>

static void dump(const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) {
        if (i < 2) printf("xx");
        else printf("%02x", b[i]);
        if (i + 1 < n) printf(":");
    }
    printf("\n");
}

int main(void) {
    unsigned char b[512];
    memset(b, 0xcc, sizeof b);
    int n = res_mkquery(QUERY, "www.example.com", C_IN, T_A, NULL, 0, NULL, b, sizeof b);
    printf("mk=%d\n", n);
    if (n > 0) dump(b, n);
    memset(b, 0xcc, sizeof b);
    n = res_mkquery(QUERY, ".", C_IN, T_A, NULL, 0, NULL, b, sizeof b);
    printf("root=%d\n", n);
    if (n > 0) dump(b, n);
    memset(b, 0xcc, sizeof b);
    printf("small=%d\n", res_mkquery(QUERY, "www.example.com", C_IN, T_A, NULL, 0, NULL, b, 8));
    memset(b, 0xcc, sizeof b);
    struct __res_state st;
    memset(&st, 0, sizeof st);
    st.options = RES_RECURSE | RES_TRUSTAD;
    n = res_nmkquery(&st, QUERY, "www.example.com", C_IN, T_A, NULL, 0, NULL, b, sizeof b);
    printf("nmk=%d\n", n);
    if (n > 0) dump(b, n);
    return 0;
}
