/* DNS name codec: dn_comp/dn_expand/dn_skipname + a compression pointer. vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <resolv.h>

int main(void) {
    unsigned char buf[256];
    int n = dn_comp("www.example.com", buf, sizeof buf, NULL, NULL);
    printf("comp_len=%d wire=%d%.3s%d%.7s%d%.3s\n", n,
           buf[0], buf+1, buf[4], buf+5, buf[12], buf+13);

    char dst[256];
    int e = dn_expand(buf, buf + n, buf, dst, sizeof dst);
    printf("expand=%d name=%s\n", e, dst);
    printf("skip=%d\n", dn_skipname(buf, buf + n));

    /* compression: msg = [3]com[0] @0 ; [3]www @5 then a pointer to @0 */
    unsigned char m[16] = {3,'c','o','m',0, 3,'w','w','w', 0xC0, 0x00};
    char d2[256];
    int e2 = dn_expand(m, m + 11, m + 5, d2, sizeof d2);
    printf("ptr_expand=%d name=%s\n", e2, d2);   /* consumed 6, "www.com" */
    return 0;
}
