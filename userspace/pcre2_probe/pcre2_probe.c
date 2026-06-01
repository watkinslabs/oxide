/* pcre2_probe — dynamic-link smoke for the cross-built libpcre2-8.so (L2).
 * Links /usr/lib/libpcre2-8.so; compiles a regex and matches a string.
 * Proves the .so loaded + works (systemd uses pcre2 for journal field
 * pattern matching). */
#include <stdio.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

int main(void) {
    int errnum; PCRE2_SIZE erroff;
    pcre2_code *re = pcre2_compile((PCRE2_SPTR)"o[a-z]+e", PCRE2_ZERO_TERMINATED,
                                   0, &errnum, &erroff, NULL);
    if (!re) { printf("pcre2_probe: compile FAIL\n"); return 1; }
    pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, NULL);
    int rc = pcre2_match(re, (PCRE2_SPTR)"oxide", 5, 0, 0, md, NULL);
    pcre2_match_data_free(md);
    pcre2_code_free(re);
    if (rc < 1) { printf("pcre2_probe: match FAIL rc=%d\n", rc); return 1; }
    printf("pcre2_probe: libpcre2-8.so OK match rc=%d\n", rc);
    return 0;
}
