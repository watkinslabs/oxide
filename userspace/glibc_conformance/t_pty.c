/* pty + tty identity vs host glibc. Deterministic: print shape-checks
 * (starts_with "/dev/pts/") and booleans, never the volatile pts number,
 * so output is byte-identical host-vs-oxide on the same kernel. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pty.h>

static int starts(const char *s, const char *pfx){ return s && strncmp(s, pfx, strlen(pfx)) == 0; }

int main(void){
    int m = -1, s = -1;
    char name[256];
    int rc = openpty(&m, &s, name, NULL, NULL);
    printf("openpty=%d\n", rc == 0);
    if (rc != 0) return 0;

    /* ptsname(master) -> "/dev/pts/N" shape */
    char *pn = ptsname(m);
    printf("ptsname_shape=%d\n", starts(pn, "/dev/pts/"));

    /* name out-param from openpty also "/dev/pts/N" */
    printf("name_shape=%d\n", starts(name, "/dev/pts/"));

    /* grantpt/unlockpt succeed on the master */
    printf("grantpt=%d unlockpt=%d\n", grantpt(m) == 0, unlockpt(m) == 0);

    /* isatty: slave is a tty (1); a regular file fd is not (0) */
    printf("isatty_slave=%d\n", isatty(s) == 1);
    int rf = open("/dev/null", O_RDONLY);
    printf("isatty_regfile=%d\n", isatty(rf) == 0);
    if (rf >= 0) close(rf);

    /* ttyname(slave) -> some "/dev/" path; just check it's a tty path shape */
    char *tn = ttyname(s);
    printf("ttyname_shape=%d\n", starts(tn, "/dev/"));

    /* ttyname_r into a caller buffer */
    char tbuf[256];
    int tr = ttyname_r(s, tbuf, sizeof tbuf);
    printf("ttyname_r=%d shape=%d\n", tr == 0, starts(tbuf, "/dev/"));

    /* ctermid returns "/dev/tty" */
    char cbuf[L_ctermid];
    printf("ctermid=%d\n", strcmp(ctermid(cbuf), "/dev/tty") == 0);

    close(m); close(s);
    return 0;
}
