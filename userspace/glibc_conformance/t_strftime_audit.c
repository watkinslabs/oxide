/* Comprehensive strftime conformance audit vs host glibc (C locale). Fixed,
   self-consistent struct tm so host & oxide derive every field identically;
   any mismatch is a strftime bug. */
#include <stdio.h>
#include <time.h>
#include <string.h>

int main(void){
    struct tm t;
    memset(&t, 0, sizeof t);
    /* Tue 2023-07-04 13:05:09 UTC, yday 184 (0-based), wday 2 */
    t.tm_year=123; t.tm_mon=6; t.tm_mday=4;
    t.tm_hour=13; t.tm_min=5; t.tm_sec=9;
    t.tm_wday=2; t.tm_yday=184; t.tm_isdst=0;
    t.tm_gmtoff=0; t.tm_zone="UTC";

    const char *specs[] = {
        "%a","%A","%b","%B","%h","%c","%C","%d","%D","%e","%F","%g","%G",
        "%H","%I","%j","%m","%M","%n","%p","%P","%r","%R","%S","%t","%T",
        "%u","%U","%V","%w","%W","%x","%X","%y","%Y","%z","%Z","%%",
        "[%Y-%m-%dT%H:%M:%S%z]", "%A %B %d, %Y",
    };
    char buf[128];
    for (size_t i=0;i<sizeof specs/sizeof specs[0];i++){
        size_t r = strftime(buf, sizeof buf, specs[i], &t);
        printf("%s -> (%zu) %s\n", specs[i], r, buf);
    }
    /* a Sunday to exercise %u/%w/%U/%W edge (wday 0) */
    struct tm s; memset(&s,0,sizeof s);
    s.tm_year=124; s.tm_mon=0; s.tm_mday=7; s.tm_wday=0; s.tm_yday=6; /* Sun 2024-01-07 */
    s.tm_zone="UTC";
    const char *wk[] = {"%u %w","%U %W %V","%G-W%V-%u"};
    for (size_t i=0;i<3;i++){ strftime(buf,sizeof buf,wk[i],&s); printf("SUN %s -> %s\n", wk[i], buf); }

    /* small buffer: strftime returns 0 and leaves contents unspecified */
    char tiny[4];
    size_t r = strftime(tiny, sizeof tiny, "%Y", &t);
    printf("tiny ret=%zu\n", r);
    return 0;
}
