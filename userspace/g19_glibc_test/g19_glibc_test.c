/* G19: exercise core glibc machinery on the oxide kernel (NOT the host
 * conformance oracle) — snprintf, malloc/realloc, string, and the full
 * buffered FILE path (fopen/fprintf/fclose). Markers go to /dev/console
 * (→serial) so the boot smoke sees them; proves the libc's FILE/malloc/
 * brk/mmap paths work against real kernel syscalls. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static int cfd;
static void mark(const char *s) {
    if (cfd >= 0) { ssize_t r = write(cfd, s, strlen(s)); (void)r; }
}

int main(void) {
    cfd = open("/dev/console", O_WRONLY);

    /* snprintf: int/str/hex → "42/ok/beef" (10 chars) */
    char buf[64];
    int n = snprintf(buf, sizeof buf, "%d/%s/%x", 42, "ok", 0xbeef);
    if (n == 10 && strcmp(buf, "42/ok/beef") == 0) mark("g19t-snprintf-ok\n");

    /* malloc: brk/mmap-backed alloc, write+read back, realloc, free */
    char *p = malloc(4096);
    if (p) {
        memset(p, 0xAB, 4096);
        if ((unsigned char)p[0] == 0xAB && (unsigned char)p[4095] == 0xAB) {
            char *q = realloc(p, 16384);
            if (q && (unsigned char)q[4095] == 0xAB) { mark("g19t-malloc-ok\n"); free(q); }
            else free(p);
        } else free(p);
    }

    /* string: strlen/strcmp/memcpy/memcmp */
    char d[8];
    memcpy(d, "abcdefg", 8);
    if (strlen("hello") == 5 && strcmp("abc", "abc") == 0 && memcmp(d, "abcdefg", 8) == 0)
        mark("g19t-string-ok\n");

    /* full buffered FILE path: fopen /dev/console, fprintf (buffered),
     * fclose flushes → write(2). The marker lands on serial via stdio. */
    FILE *f = fopen("/dev/console", "w");
    if (f) {
        fprintf(f, "g19t-stdio-%d-%s\n", 7, "ok");
        fclose(f);
    }

    mark("g19t-done\n");
    return 0;
}
