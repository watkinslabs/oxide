/* lz4_probe — dynamic-link smoke for the cross-built liblz4.so (L2).
 * Links /usr/lib/liblz4.so; round-trips a buffer through compress +
 * decompress and checks it matches. Proves the .so loaded + works. */
#include <stdio.h>
#include <string.h>
#include <lz4.h>

int main(void) {
    const char *msg = "oxide-lz4-roundtrip-test-payload";
    int in = (int)strlen(msg) + 1;
    char comp[256], out[256];
    int c = LZ4_compress_default(msg, comp, in, sizeof comp);
    if (c <= 0) { printf("lz4_probe: compress FAIL\n"); return 1; }
    int d = LZ4_decompress_safe(comp, out, c, sizeof out);
    if (d != in || memcmp(out, msg, in) != 0) {
        printf("lz4_probe: roundtrip FAIL\n"); return 1;
    }
    printf("lz4_probe: liblz4.so OK v=%d %d->%d->%d\n",
           LZ4_versionNumber(), in, c, d);
    return 0;
}
