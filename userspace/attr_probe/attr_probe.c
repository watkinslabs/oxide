/* attr_probe — dynamic-link smoke for the cross-built libattr.so (L2;
 * acl's dep / xattr handling). Links /usr/lib/libattr.so; calls
 * attr_get on a path with a bogus attribute name (expects failure, not
 * a crash) to prove the .so loaded + the symbol resolves + runs. */
#include <stdio.h>
#include <errno.h>
/* attr's installed <attr/attributes.h> decorates each decl with EXPORT,
 * a build-time visibility macro it doesn't define for consumers. Define
 * it as plain extern (a known attr packaging quirk). */
#define EXPORT extern
#include <attr/attributes.h>
int main(void) {
    char val[64];
    int len = (int)sizeof(val);
    /* No such attribute → returns -1; we only need the call to resolve
     * + run through libattr without crashing. */
    int rc = attr_get("/", "user.oxide_nonexistent", val, &len, 0);
    if (rc == 0) { printf("attr_probe: unexpected success\n"); return 1; }
    printf("attr_probe: libattr.so OK (attr_get rc=%d errno=%d)\n", rc, errno);
    return 0;
}
