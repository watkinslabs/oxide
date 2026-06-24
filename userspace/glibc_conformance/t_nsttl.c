/* ns_format_ttl + ns_parse_ttl + ns_datetosecs — pure libresolv codecs.
 * Diff vs host glibc (-lresolv). */
#define _GNU_SOURCE
#include <stdio.h>
#include <arpa/nameser.h>

int main(void) {
    char b[64];
    unsigned long ttls[] = {90061, 3600, 0, 1, 604800, 86400, 61, 119, 93784, 7200};
    for (unsigned i = 0; i < sizeof ttls/sizeof *ttls; i++) {
        int r = ns_format_ttl(ttls[i], b, sizeof b);
        printf("fmt %lu r=%d [%s]\n", ttls[i], r, b);
    }
    const char *ps[] = {"1D1H1M1S", "3600", "2w", "1h30m", "90", "1W1D", "5S", "1w2d3h4m5s"};
    for (unsigned i = 0; i < sizeof ps/sizeof *ps; i++) {
        unsigned long t = 0; int p = ns_parse_ttl(ps[i], &t);
        printf("parse %s r=%d t=%lu\n", ps[i], p, t);
    }
    /* error cases */
    unsigned long t = 0;
    printf("parse_empty r=%d\n", ns_parse_ttl("", &t));
    printf("parse_badunit r=%d\n", ns_parse_ttl("5x", &t));
    printf("parse_leadunit r=%d\n", ns_parse_ttl("h", &t));

    const char *dates[] = {
        "19900101000000", "20240229010203", "21060207062815",
        "19891231235959", "20241301000000", "2024010100000x", "short"
    };
    for (unsigned i = 0; i < sizeof dates/sizeof *dates; i++) {
        int err = -1;
        unsigned v = ns_datetosecs(dates[i], &err);
        printf("date %s v=%u err=%d\n", dates[i], v, err);
    }
    return 0;
}
