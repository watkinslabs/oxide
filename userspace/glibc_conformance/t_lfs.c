/* LFS *64 aliases + mkostemps + strtof64/wcstof64. vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <locale.h>
#include <unistd.h>
#include <sys/uio.h>
#include <wchar.h>

int main(void) {
    char t1[] = "/tmp/lfs_XXXXXX"; int f1 = mkstemp64(t1);
    char t2[] = "/tmp/lfs_XXXXXX.log"; int f2 = mkostemps(t2, 4, O_CLOEXEC);
    printf("mkstemp64=%d mkostemps=%d ends_log=%d cloexec=%d\n",
           f1 >= 0, f2 >= 0, strcmp(t2 + strlen(t2) - 4, ".log") == 0,
           f2 >= 0 && (fcntl(f2, F_GETFD) & FD_CLOEXEC) != 0);

    /* preadv64/pwritev64 round-trip */
    struct iovec wv[2] = { { "AB", 2 }, { "CD", 2 } };
    pwritev64(f1, wv, 2, 0);
    char b0[2], b1[2];
    struct iovec rv[2] = { { b0, 2 }, { b1, 2 } };
    ssize_t n = preadv64(f1, rv, 2, 0);
    printf("pv64=%zd data=%d\n", n, memcmp(b0, "AB", 2) == 0 && memcmp(b1, "CD", 2) == 0);

    printf("strtof64=%d wcstof64=%d\n", strtof64("3.25", NULL) == 3.25, wcstof64(L"2.5", NULL) == 2.5);
    locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    printf("strtofN_l=%d %d\n", strtof32_l("1.5", NULL, loc) == 1.5f, strtof64_l("4.5", NULL, loc) == 4.5);
    freelocale(loc);
    close(f1); close(f2); unlink(t1); unlink(t2);
    return 0;
}
