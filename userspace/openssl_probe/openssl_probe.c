/* openssl_probe — dynamic-link smoke for the cross-built libssl.so +
 * libcrypto.so (L2; systemd resolved DoT/DNSSEC + journal TLS).
 * Links /usr/lib/libssl.so + libcrypto.so. Computes a SHA-256 digest via
 * libcrypto's EVP API and creates+frees a TLS client context via libssl,
 * proving both .so's loaded + resolved + the crypto/TLS cores work. */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
int main(void) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    const char *in = "oxide";
    if (EVP_Digest(in, strlen(in), md, &mdlen, EVP_sha256(), NULL) != 1
        || mdlen != 32) {
        printf("openssl_probe: EVP_Digest FAIL\n"); return 1;
    }
    const SSL_METHOD *m = TLS_client_method();
    SSL_CTX *ctx = m ? SSL_CTX_new(m) : NULL;
    if (!ctx) { printf("openssl_probe: SSL_CTX_new FAIL\n"); return 1; }
    SSL_CTX_free(ctx);
    printf("openssl_probe: libssl+libcrypto OK %s sha256[0]=%02x\n",
           OpenSSL_version(OPENSSL_VERSION), md[0]);
    return 0;
}
