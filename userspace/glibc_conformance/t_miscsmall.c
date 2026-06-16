/* Small libc gaps: glob_pattern_p (pure), lchmod (fchmodat2), dysize. Diff vs
 * host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

extern int glob_pattern_p(const char *, int);
extern int dysize(int);

int main(void) {
    printf("gpp star=%d q=%d set=%d lit=%d esc=%d openonly=%d\n",
        glob_pattern_p("a*b", 1), glob_pattern_p("a?b", 1),
        glob_pattern_p("a[xy]z", 1), glob_pattern_p("plain", 1),
        glob_pattern_p("a\\*b", 1), glob_pattern_p("a[bc", 1));

    printf("dysize 2000=%d 1900=%d 1996=%d 2025=%d\n",
        dysize(2000), dysize(1900), dysize(1996), dysize(2025));

    /* lchmod on a regular file succeeds; on a symlink ⇒ EOPNOTSUPP. */
    char f[] = "/tmp/lcm_XXXXXX"; int fd = mkstemp(f); close(fd);
    int r1 = lchmod(f, 0640);
    struct stat st; stat(f, &st);
    char tgt[] = "/tmp/lct_XXXXXX"; int tf = mkstemp(tgt); close(tf);
    char sl[] = "/tmp/lcs_XXXXXX"; close(mkstemp(sl)); unlink(sl); symlink(tgt, sl);
    errno = 0; int r2 = lchmod(sl, 0600); int e2 = r2 < 0 ? errno : 0;
    printf("lchmod_reg=%d mode=%o lchmod_sym=%d errno=%d\n", r1, st.st_mode & 0777, r2, e2);

    unlink(f); unlink(tgt); unlink(sl);
    return 0;
}
