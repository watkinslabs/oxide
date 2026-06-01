/* systemd_probe — dynamic-link smoke for the cross-built libsystemd.so
 * (Track D6: systemd). Links /usr/lib/libsystemd.so; generates a random
 * 128-bit ID via sd_id128_randomize and formats it, proving the .so
 * loaded + resolved + a real systemd library call works on musl. */
#include <stdio.h>
#include <systemd/sd-id128.h>
int main(void) {
    sd_id128_t id;
    int r = sd_id128_randomize(&id);
    if (r < 0) { printf("systemd_probe: sd_id128_randomize FAIL r=%d\n", r); return 1; }
    char s[SD_ID128_STRING_MAX];
    sd_id128_to_string(id, s);
    /* a valid 128-bit id renders as 32 lowercase hex chars */
    int n = 0; for (const char *p = s; *p; p++) n++;
    if (n != 32) { printf("systemd_probe: bad id len %d (%s)\n", n, s); return 1; }
    printf("systemd_probe: libsystemd.so OK id=%s\n", s);
    return 0;
}
