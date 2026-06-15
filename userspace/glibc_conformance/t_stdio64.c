/* stdio64: LFS *64 aliases + fpos round-trip, setvbuf/__flbf/__fbufsize,
   putw/getw, popen/pclose. Differential vs host glibc (the harness runs our
   libc against the host kernel; /bin/sh exists on the host). The __f* values
   are FILE-specific, so we assert the glibc CONTRACT (booleans), not raw sizes. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void){
    const char *p = "/tmp/oxide_stdio64.dat";

    /* fopen64 "w+", fwrite + ftello64/fseeko64 round-trip. */
    FILE *f = fopen64(p, "w+");
    if(!f){ printf("fopen64 fail\n"); return 1; }
    const char *msg = "abcdefghij";
    fwrite(msg, 1, 10, f);
    printf("ftello64=%lld\n", (long long)ftello64(f));
    fseeko64(f, 3, SEEK_SET);
    printf("after_seek ftello64=%lld getc=%c\n", (long long)ftello64(f), fgetc(f));

    /* fgetpos64 / fsetpos64 round-trip. */
    fpos64_t pos;
    fseeko64(f, 7, SEEK_SET);
    fgetpos64(f, &pos);
    fseeko64(f, 0, SEEK_SET);
    fsetpos64(f, &pos);
    printf("fsetpos64 tell=%lld getc=%c\n", (long long)ftello64(f), fgetc(f));
    fclose(f);

    /* setvbuf(_IOLBF): __flbf nonzero, __fbufsize > 0. */
    FILE *w = fopen(p, "w");
    setvbuf(w, NULL, _IOLBF, 0);
    printf("flbf=%d fbufsize_pos=%d\n", __flbf(w) != 0, __fbufsize(w) > 0);
    /* "w" stream is writable, not readable. */
    printf("writable=%d readable=%d\n", __fwritable(w) != 0, __freadable(w) != 0);
    fputc('X', w);
    printf("fwriting_after_put=%d\n", __fwriting(w) != 0);
    fclose(w);

    /* putw/getw int round-trip. */
    FILE *iw = fopen(p, "w");
    putw(0x12345678, iw);
    fclose(iw);
    FILE *ir = fopen(p, "r");
    int got = getw(ir);
    printf("getw=0x%x freading_after_get=%d\n", got, __freading(ir) != 0);
    fclose(ir);

    /* popen("echo hi","r") -> fgets -> "hi"; pclose == 0. The differential
       harness runs our libc via LD_LIBRARY_PATH; clear it so the forked
       /bin/sh loads the system libc, not our partial one (host is unaffected). */
    unsetenv("LD_LIBRARY_PATH");
    FILE *pp = popen("echo hi", "r");
    if(!pp){ printf("popen fail\n"); return 1; }
    char line[64] = {0};
    fgets(line, sizeof line, pp);
    line[strcspn(line, "\n")] = 0;
    int rc = pclose(pp);
    printf("popen_line=%s pclose=%d\n", line, rc);

    unlink(p);
    return 0;
}
