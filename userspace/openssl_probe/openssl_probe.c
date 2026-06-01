/* openssl_probe — dynamic-link smoke for libssl.so + libcrypto.so (L2;
 * systemd resolved DoT/DNSSEC + journal TLS). Links -lssl -lcrypto so
 * both are DT_NEEDED. Computes a SHA-256 digest via libcrypto's EVP API.
 *
 * NOTE: rcS runs this on x86 only. On aarch64, libcrypto.so HANGS during
 * its load-time constructor (before main even runs — verified: a probe
 * that only prints + takes symbol addresses never reached main on arm).
 * That makes openssl currently unloadable on arm → tracked as a HARD
 * systemd-on-arm blocker in TASKS.md, to root-cause in Track D6. */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
int main(void) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    if (EVP_Digest("oxide", 5, md, &mdlen, EVP_sha256(), NULL) != 1 || mdlen != 32) {
        printf("openssl_probe: EVP_Digest FAIL\n"); return 1;
    }
    printf("openssl_probe: libcrypto+libssl OK %s sha256[0]=%02x\n",
           OPENSSL_VERSION_TEXT, md[0]);
    return 0;
}
