/* libidn2_probe — dynamic-link smoke for the cross-built libidn2.so (L2;
 * systemd-resolved IDNA). Links /usr/lib/libidn2.so (which DT_NEEDEDs
 * libunistring.so, so loading it exercises that chain). Converts a
 * UTF-8 IDN label to ASCII (Punycode) and checks the xn-- output,
 * proving the .so loaded + resolved + the IDNA core works. */
#include <stdio.h>
#include <string.h>
#include <idn2.h>
int main(void) {
    char *out = NULL;
    /* "bücher" → "xn--bcher-kva" */
    int rc = idn2_to_ascii_8z("b\xc3\xbc" "cher", &out, 0);
    if (rc != IDN2_OK || out == NULL) {
        printf("libidn2_probe: idn2_to_ascii_8z FAIL rc=%d (%s)\n", rc, idn2_strerror(rc));
        return 1;
    }
    int ok = strncmp(out, "xn--", 4) == 0;
    printf("libidn2_probe: libidn2.so OK \"b\\xc3\\xbccher\"->%s%s\n",
           out, ok ? "" : " (UNEXPECTED)");
    idn2_free(out);
    return ok ? 0 : 1;
}
