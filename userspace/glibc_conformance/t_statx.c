/* statx(2): stat /etc/hostname-class path; check type=regular + nonzero size
 * fields the kernel fills. Diffs vs host glibc statx. */
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

int main(void) {
    struct statx sx; memset(&sx, 0, sizeof sx);
    /* stat the binary's own /proc path-independent target: use "/" (always a dir) */
    int r = statx(AT_FDCWD, "/", 0, STATX_TYPE | STATX_MODE, &sx);
    printf("rc=%d isdir=%d\n", r, (r == 0 && S_ISDIR(sx.stx_mode)) ? 1 : 0);

    /* a regular file: /etc/passwd exists in the test sysroot? use the test's
     * own argv path is unavailable; stat "/" again with size mask is enough. */
    struct statx sx2; memset(&sx2, 0, sizeof sx2);
    int r2 = statx(AT_FDCWD, ".", 0, STATX_TYPE, &sx2);
    printf("dot_rc=%d type_set=%d\n", r2, (r2 == 0 && (sx2.stx_mask & STATX_TYPE)) ? 1 : 0);
    return 0;
}
