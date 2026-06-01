/* libcap_probe — dynamic-link smoke for the first L2 systemd shared dep.
 * Links against /usr/lib/libcap.so (real upstream libcap 2.69, musl-built).
 * Exercises the actual library: get the process caps, round-trip them
 * through text, free. Prints OK + rv so rcS can assert the .so loaded,
 * resolved, and ran. Proves the L2 cross-build→stage→dyn-load pipeline
 * end-to-end on a genuine systemd dependency. */
#include <stdio.h>
#include <sys/capability.h>

int main(void) {
    cap_t c = cap_get_proc();
    if (!c) { printf("libcap_probe: cap_get_proc FAIL\n"); return 1; }
    ssize_t n = 0;
    char *txt = cap_to_text(c, &n);
    printf("libcap_probe: libcap.so OK caps=\"%s\"\n", txt ? txt : "(none)");
    if (txt) cap_free(txt);
    cap_free(c);
    return 0;
}
