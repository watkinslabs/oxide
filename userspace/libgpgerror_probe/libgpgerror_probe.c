/* libgpgerror_probe — dynamic-link smoke for the cross-built
 * libgpg-error.so (L2; libgcrypt's dep, systemd unconditional DEPENDS).
 * Links /usr/lib/libgpg-error.so; maps an error code to its string and
 * checks the runtime version. Proves the .so loaded + resolved. */
#include <stdio.h>
#include <string.h>
#include <gpg-error.h>
int main(void) {
    const char *v = gpg_error_check_version("1.0");
    if (!v) { printf("libgpgerror_probe: version FAIL\n"); return 1; }
    const char *s = gpg_strerror(GPG_ERR_NO_ERROR);
    if (!s || strstr(s, "Success") == NULL) {
        printf("libgpgerror_probe: strerror FAIL (%s)\n", s ? s : "(null)");
        return 1;
    }
    gpg_error_t e = gpg_err_make(GPG_ERR_SOURCE_USER_1, GPG_ERR_INV_VALUE);
    if (gpg_err_code(e) != GPG_ERR_INV_VALUE) {
        printf("libgpgerror_probe: code roundtrip FAIL\n"); return 1;
    }
    printf("libgpgerror_probe: libgpg-error.so OK ver=%s\n", v);
    return 0;
}
