#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

extern int __open_2(const char *, int);
extern int __open64_2(const char *, int);
extern int __openat_2(int, const char *, int);
extern int __openat64_2(int, const char *, int);
extern mqd_t __mq_open_2(const char *, int);

static int run_call(int which, int flags) {
    errno = 0;
    switch (which) {
    case 0:
        return __open_2("/definitely/no/such/file", flags);
    case 1:
        return __open64_2("/definitely/no/such/file", flags);
    case 2:
        return __openat_2(AT_FDCWD, "/definitely/no/such/file", flags);
    case 3:
        return __openat64_2(AT_FDCWD, "/definitely/no/such/file", flags);
    default:
        return __mq_open_2("/oxide-definitely-no-such-queue", flags);
    }
}

static void probe(const char *label, int which, int flags) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        int r = run_call(which, flags);
        printf("%s child r=%d errno=%d\n", label, r, errno);
        fflush(stdout);
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) {
        printf("%s parent sig=%d\n", label, WTERMSIG(st));
    } else {
        printf("%s parent exit=%d\n", label, WEXITSTATUS(st));
    }
}

int main(void) {
    probe("open_rd", 0, O_RDONLY);
    probe("open_creat", 0, O_WRONLY | O_CREAT);
    probe("open_tmpfile", 0, O_TMPFILE | O_RDWR);
    probe("open64_rd", 1, O_RDONLY);
    probe("openat_rd", 2, O_RDONLY);
    probe("openat_creat", 2, O_WRONLY | O_CREAT);
    probe("openat64_rd", 3, O_RDONLY);
    probe("mq_rd", 4, O_RDONLY);
    probe("mq_creat", 4, O_RDWR | O_CREAT);
    return 0;
}
