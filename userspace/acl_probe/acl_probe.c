/* acl_probe — dynamic-link smoke for the cross-built libacl.so (L2;
 * systemd journal file ACLs). Links /usr/lib/libacl.so (which DT_NEEDEDs
 * libattr.so, so loading it exercises that chain). Parses an ACL from
 * text + frees it, proving the .so loaded + resolved + the parser works. */
#include <stdio.h>
/* acl's installed <sys/acl.h> decorates decls with EXPORT, a build-time
 * visibility macro it doesn't define for consumers (same quirk as attr).
 * Define it as plain extern. */
#define EXPORT extern
#include <sys/acl.h>
int main(void) {
    acl_t a = acl_from_text("u::rw-,g::r--,o::r--");
    if (a == (acl_t)NULL) { printf("acl_probe: acl_from_text FAIL\n"); return 1; }
    ssize_t n = acl_size(a);
    acl_free(a);
    if (n <= 0) { printf("acl_probe: acl_size FAIL (%zd)\n", n); return 1; }
    printf("acl_probe: libacl.so OK (acl_size=%zd)\n", n);
    return 0;
}
