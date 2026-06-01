/* utillinux_probe — dynamic-link smoke for the cross-built util-linux
 * shared libs (L2, mandatory systemd deps). Links /usr/lib/libmount.so
 * (which DT_NEEDEDs libblkid.so + libuuid.so, so loading it exercises
 * the whole chain) and libuuid directly. Calls a simple API from
 * each and prints OK. Proves the .so's loaded + resolved. */
#include <stdio.h>
#include <libmount/libmount.h>
#include <uuid/uuid.h>

int main(void) {
    /* libmount: create + free a context (touches the library). */
    struct libmnt_context *cxt = mnt_new_context();
    if (!cxt) { printf("utillinux_probe: mnt_new_context FAIL\n"); return 1; }
    mnt_free_context(cxt);
    /* libuuid: generate + unparse a UUID. */
    uuid_t u; char s[37];
    uuid_generate(u);
    uuid_unparse(u, s);
    if (s[8] != '-' || s[36] != 0) { printf("utillinux_probe: uuid FAIL\n"); return 1; }
    printf("utillinux_probe: libmount.so + libuuid.so OK uuid=%s\n", s);
    return 0;
}
