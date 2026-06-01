/* kmod_probe — dynamic-link smoke for the cross-built libkmod.so (L2;
 * systemd-modules-load / udev modalias link dep). Links /usr/lib/libkmod.so;
 * creates + frees a kmod context (no real modules needed — oxide's kernel
 * is monolithic) to prove the .so loaded + the symbols resolve. */
#include <stdio.h>
#include <libkmod.h>
int main(void) {
    struct kmod_ctx *ctx = kmod_new(NULL, NULL);
    if (!ctx) { printf("kmod_probe: kmod_new FAIL\n"); return 1; }
    /* Touch the library a little more: query the configured module dir. */
    const char *dir = kmod_get_dirname(ctx);
    kmod_unref(ctx);
    printf("kmod_probe: libkmod.so OK dir=%s\n", dir ? dir : "(null)");
    return 0;
}
