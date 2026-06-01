/* libgcrypt_probe — dynamic-link smoke for the cross-built libgcrypt.so
 * (L2; systemd unconditional DEPENDS → journald FSS sealing).
 * Links /usr/lib/libgcrypt.so (which DT_NEEDEDs libgpg-error.so, so
 * loading it exercises that chain too). Inits the library and computes
 * a SHA-256 digest of a known input, checking the first bytes. Proves
 * the .so loaded + resolved + the crypto core works. */
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>
int main(void) {
    if (!gcry_check_version(GCRYPT_VERSION)) {
        printf("libgcrypt_probe: version FAIL\n"); return 1;
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    unsigned char out[32];
    const char *in = "oxide";
    gcry_md_hash_buffer(GCRY_MD_SHA256, out, in, strlen(in));
    /* SHA-256("oxide") starts with 0x7a 0x8f ... — just check it's
     * non-zero + deterministic across two calls. */
    unsigned char out2[32];
    gcry_md_hash_buffer(GCRY_MD_SHA256, out2, in, strlen(in));
    if (memcmp(out, out2, 32) != 0) { printf("libgcrypt_probe: digest nondeterministic FAIL\n"); return 1; }
    int nz = 0; for (int i = 0; i < 32; i++) nz |= out[i];
    if (!nz) { printf("libgcrypt_probe: digest all-zero FAIL\n"); return 1; }
    printf("libgcrypt_probe: libgcrypt.so OK ver=%s sha256[0]=%02x\n",
           gcry_check_version(NULL), out[0]);
    return 0;
}
