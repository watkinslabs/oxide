/* libxcrypt_probe — dynamic-link smoke for the cross-built libcrypt.so
 * (L2). Links /usr/lib/libcrypt.so; hashes a password with a $6$
 * (sha512crypt) salt and checks the result is a well-formed $6$ hash
 * that re-verifies. Proves real crypt() (what pam_unix/shadow use for
 * /etc/shadow) works via the shared lib. */
#include <stdio.h>
#include <string.h>
#include <crypt.h>

int main(void) {
    const char *pw = "oxide-secret";
    const char *salt = "$6$abcdefgh";
    char *h = crypt(pw, salt);
    if (!h || strncmp(h, "$6$", 3) != 0) {
        printf("libxcrypt_probe: crypt FAIL\n"); return 1;
    }
    /* re-verify: hashing again with the produced hash as salt must match */
    char want[256];
    strncpy(want, h, sizeof want - 1); want[sizeof want - 1] = 0;
    char *h2 = crypt(pw, want);
    if (!h2 || strcmp(h, h2) != 0) {
        printf("libxcrypt_probe: reverify FAIL\n"); return 1;
    }
    printf("libxcrypt_probe: libcrypt.so OK sha512crypt verified\n");
    return 0;
}
