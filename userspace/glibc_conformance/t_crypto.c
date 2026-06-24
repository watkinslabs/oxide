/* catgets default-string fallback, net/if name<->index round-trip on the
 * stable "lo" loopback, backtrace depth/symbol counts, mallopt boolean, vs
 * host glibc. The DES setkey/encrypt/ecb_crypt + cfree symbols this cluster
 * also ships are validated separately (Rust FIPS-vector unit tests in
 * crates/user/glibc/src/crypt/des.rs) — modern host glibc has removed those
 * symbols, so there is no live host oracle to diff them here. Backtrace
 * addresses are non-deterministic, so we print only the COUNTS. */
#define _GNU_SOURCE
#include <nl_types.h>
#include <net/if.h>
#include <execinfo.h>
#include <crypt.h>
#include <errno.h>
#include <malloc.h>
#include <mcheck.h>
#include <stdio.h>
#include <string.h>

/* Keep frame pointers in the call chain so the frame-pointer-walk backtrace
 * has a chain to follow even under -O2 (host glibc uses DWARF CFI and is
 * frame-pointer-agnostic; we match by preserving the frames). */
__attribute__((noinline, optimize("no-omit-frame-pointer")))
static int depth3(void **bt, int cap) { int r = backtrace(bt, cap); __asm__ volatile(""); return r; }
__attribute__((noinline, optimize("no-omit-frame-pointer")))
static int depth2(void **bt, int cap) { int r = depth3(bt, cap); __asm__ volatile(""); return r; }

int main(void) {
    /* catgets: missing catalog -> catopen returns (nl_catd)-1, catgets returns
     * the supplied default, catclose on the sentinel is -1. */
    nl_catd c = catopen("oxide_missing_catalog", 0);
    printf("catopen_fail=%d\n", c == (nl_catd) -1);
    char *m = catgets(c, 1, 1, "DEFAULT_STRING");
    printf("catgets=%s\n", m);
    printf("catclose=%d\n", catclose(c));

    /* net/if: "lo" is index>0 and round-trips back to "lo". */
    unsigned idx = if_nametoindex("lo");
    char nm[IF_NAMESIZE];
    char *r = if_indextoname(idx, nm);
    printf("lo_index_positive=%d\n", idx > 0);
    printf("lo_roundtrip=%d\n", (r != NULL) && strcmp(nm, "lo") == 0);

    /* backtrace from a known >=2-deep call chain; print counts, not addresses. */
    void *bt[64];
    int n = depth2(bt, 64);
    char **syms = backtrace_symbols(bt, n);
    printf("backtrace_ge2=%d\n", n >= 2);
    printf("backtrace_symbols_nonnull=%d\n", syms != NULL);

    /* mallopt accepts a documented tunable -> 1. */
    printf("mallopt=%d\n", mallopt(M_TRIM_THRESHOLD, 128 * 1024));
    errno = 0;
    printf("malloc_info_badopt=%d errno=%d\n", malloc_info(1, stdout), errno);
    errno = 0;
    mcheck_check_all();
    printf("mcheck_check_all_errno=%d\n", errno);
    printf("checksalt=%d %d\n", crypt_checksalt("$6$salt"), crypt_checksalt("") == CRYPT_SALT_INVALID);
    unsigned char rb[16]; for (int i = 0; i < 16; i++) rb[i] = (unsigned char)(i * 17);
    char salt[CRYPT_GENSALT_OUTPUT_SIZE];
    printf("gensalt_r=%s\n", crypt_gensalt_r("$6$", 0, (const char *)rb, 16, salt, sizeof salt));

    return 0;
}
