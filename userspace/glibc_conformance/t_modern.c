/* Modern syscall wrappers (unprivileged subset): getcpu, getdents64,
 * getdirentries, close_range, renameat2, readahead. Diff vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sched.h>
#include <string.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif

int main(void) {
    unsigned cpu = 9999, node = 9999;
    int gc = getcpu(&cpu, &node);
    printf("getcpu=%d cpu_ok=%d\n", gc, cpu < 4096);

    int d = open(".", O_RDONLY | O_DIRECTORY);
    char buf[2048];
    long n = getdents64(d, buf, sizeof buf);
    printf("getdents64_ok=%d\n", n > 0);
    lseek(d, 0, SEEK_SET);
    off_t base = -1;
    ssize_t gd = getdirentries(d, buf, sizeof buf, &base);
    printf("getdirentries_ok=%d base_set=%d\n", gd > 0, base >= 0);
    close(d);

    int fd = dup(1);
    int cr = close_range(fd, fd, 0);
    int after = fcntl(fd, F_GETFD); /* -1/EBADF after close_range */
    printf("close_range=%d closed=%d\n", cr, after == -1);

    char a[] = "/tmp/rn2a_XXXXXX"; int fa = mkstemp(a); close(fa);
    char b[64]; snprintf(b, sizeof b, "%s.new", a);
    int rn = renameat2(AT_FDCWD, a, AT_FDCWD, b, 0);
    /* NOREPLACE onto an existing target must fail */
    char c[] = "/tmp/rn2c_XXXXXX"; int fc = mkstemp(c); close(fc);
    int rn2 = renameat2(AT_FDCWD, b, AT_FDCWD, c, RENAME_NOREPLACE);
    printf("renameat2=%d noreplace_fail=%d\n", rn, rn2 != 0);
    unlink(b); unlink(c);

    char rf[] = "/tmp/rah_XXXXXX"; int fr = mkstemp(rf);
    write(fr, "hello world", 11);
    int ra = readahead(fr, 0, 11);
    printf("readahead=%d\n", ra);
    close(fr); unlink(rf);
    return 0;
}
