/* zstd_probe — dynamic-link smoke for the cross-built libzstd.so (L2).
 * Links /usr/lib/libzstd.so; round-trips a buffer through compress +
 * decompress and checks it matches. Proves the .so loaded, resolved,
 * and works on a genuine systemd dependency (journal compression). */
#include <stdio.h>
#include <string.h>
#include <zstd.h>

int main(void) {
    const char *msg = "oxide-zstd-roundtrip-test-payload";
    size_t in = strlen(msg) + 1;
    char comp[256], out[256];
    size_t c = ZSTD_compress(comp, sizeof comp, msg, in, 3);
    if (ZSTD_isError(c)) { printf("zstd_probe: compress FAIL\n"); return 1; }
    size_t d = ZSTD_decompress(out, sizeof out, comp, c);
    if (ZSTD_isError(d) || d != in || memcmp(out, msg, in) != 0) {
        printf("zstd_probe: roundtrip FAIL\n"); return 1;
    }
    printf("zstd_probe: libzstd.so OK v=%u %zu->%zu->%zu\n",
           ZSTD_versionNumber(), in, c, d);
    return 0;
}
