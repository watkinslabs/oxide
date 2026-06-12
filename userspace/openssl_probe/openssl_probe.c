/* openssl_probe — dynamic-link smoke for libssl.so + libcrypto.so (L2;
 * systemd resolved DoT/DNSSEC + journal TLS). Links -lssl -lcrypto so
 * both are DT_NEEDED. Computes a SHA-256 digest via libcrypto's EVP API.
 *
 * RESOLVED on aarch64 (was a HARD systemd-on-arm blocker): libcrypto.so
 * used to HANG in its load-time constructor before main. It no longer
 * reproduces — VERIFIED LIVE 2026-06-12: this probe runs on aarch64 and
 * prints the EVP SHA-256 digest. The fix came from earlier kernel work
 * (this comment was stale); attribution test confirmed it is NOT
 * AT_HWCAP-dependent (works with AT_HWCAP advertising 0 or the ARMv8-A
 * baseline). Root cause of the original hang not pinned down — left as a
 * note rather than a guess. */
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
    // Machine-checkable line for boot-smoke-probe.sh (gates this in CI on
    // BOTH arches now that aarch64 no longer hangs).
    printf("openssl_probe: PASS\n");
    return 0;
}
