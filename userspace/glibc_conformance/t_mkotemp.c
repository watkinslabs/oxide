/* mkostemp (O_CLOEXEC), mkstemps (suffix), waitid (CLD_EXITED/status),
 * futimesat (set times). Diff vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>

int main(void) {
    char t1[] = "/tmp/mko_XXXXXX";
    int fd = mkostemp(t1, O_CLOEXEC);
    int cloexec = (fd >= 0) && (fcntl(fd, F_GETFD) & FD_CLOEXEC);
    printf("mkostemp_ok=%d cloexec=%d\n", fd >= 0, cloexec);
    if (fd >= 0) { close(fd); unlink(t1); }

    char t2[] = "/tmp/mks_XXXXXX.txt";
    int fd2 = mkstemps(t2, 4);
    printf("mkstemps_ok=%d ends_txt=%d\n", fd2 >= 0, strcmp(t2 + strlen(t2) - 4, ".txt") == 0);
    if (fd2 >= 0) { close(fd2); unlink(t2); }

    pid_t p = fork();
    if (p == 0) _exit(7);
    siginfo_t si; memset(&si, 0, sizeof si);
    int r = waitid(P_PID, p, &si, WEXITED);
    printf("waitid=%d code_exited=%d status=%d\n", r, si.si_code == CLD_EXITED, si.si_status);

    char t3[] = "/tmp/fut_XXXXXX"; int f3 = mkstemp(t3); close(f3);
    printf("futimesat=%d\n", futimesat(AT_FDCWD, t3, NULL));
    unlink(t3);
    return 0;
}
