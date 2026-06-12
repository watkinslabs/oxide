/* /bin/pid_identity_probe — single pid-identity acceptance test.
 *
 * Linux has ONE pid per process: fork() returns the child's PID, the child's
 * getpid() returns the SAME value, and waitpid(that_pid) reaps it returning
 * the same value. oxide used to leak a second identity — fork() returned the
 * opaque internal tid (0x1000+) while getpid() returned the small vpid — so
 * these three disagreed and pidfile-based wait/kill broke. This proves they
 * now agree. */
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>

/* Field 1 of /proc/self/stat is the PID. Returns it, or -1. */
static long self_stat_pid(void) {
    int fd = open("/proc/self/stat", O_RDONLY);
    if (fd < 0) return -1;
    char b[256]; ssize_t n = read(fd, b, sizeof b - 1); close(fd);
    if (n <= 0) return -1;
    b[n] = 0;
    return strtol(b, (char **)0, 10);   /* field 1 = pid */
}

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) { printf("pid_identity_probe: FAIL pipe\n"); return 1; }
    pid_t parent_pid = getpid();
    pid_t pid = fork();
    if (pid < 0) { printf("pid_identity_probe: FAIL fork\n"); return 1; }
    if (pid == 0) {
        /* child: report own getpid() + getppid() to the parent, then exit 42. */
        close(fds[0]);
        pid_t buf[2] = { getpid(), getppid() };
        ssize_t _ = write(fds[1], buf, sizeof buf);
        (void)_;
        close(fds[1]);
        _exit(42);
    }
    /* parent */
    close(fds[1]);
    pid_t buf[2] = { -1, -1 };
    if (read(fds[0], buf, sizeof buf) != (ssize_t)sizeof buf) {
        printf("pid_identity_probe: FAIL pipe-read\n"); return 1;
    }
    pid_t child_getpid = buf[0], child_getppid = buf[1];
    close(fds[0]);
    int st = 0;
    pid_t w = waitpid(pid, &st, 0);

    if (child_getpid != pid) {
        printf("pid_identity_probe: FAIL fork=%d != child getpid=%d\n", (int)pid, (int)child_getpid);
        return 1;
    }
    if (w != pid) {
        printf("pid_identity_probe: FAIL waitpid=%d != fork=%d\n", (int)w, (int)pid);
        return 1;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 42) {
        printf("pid_identity_probe: FAIL status=0x%x\n", st);
        return 1;
    }
    if (pid == parent_pid) {
        printf("pid_identity_probe: FAIL child pid == parent pid\n");
        return 1;
    }
    if (child_getppid != parent_pid) {
        printf("pid_identity_probe: FAIL child getppid=%d != parent getpid=%d\n",
               (int)child_getppid, (int)parent_pid);
        return 1;
    }
    long sp = self_stat_pid();
    if (sp != (long)parent_pid) {
        printf("pid_identity_probe: FAIL /proc/self/stat pid=%ld != getpid=%d\n",
               sp, (int)parent_pid);
        return 1;
    }
    /* B118: pgid/sid live in VPID space. The opaque internal tid starts at
     * 0x1000 (4096); a leaked internal tid here would be >= 4096. They must
     * also be self-consistent: getpgid(0)==getpgid(getpid()), getsid likewise. */
    pid_t pg0 = getpgid(0), pgp = getpgid(parent_pid);
    pid_t sd0 = getsid(0),  sdp = getsid(parent_pid);
    if (pg0 != pgp || sd0 != sdp) {
        printf("pid_identity_probe: FAIL getpgid(0)=%d!=getpgid(pid)=%d or getsid(0)=%d!=getsid(pid)=%d\n",
               (int)pg0, (int)pgp, (int)sd0, (int)sdp);
        return 1;
    }
    if (pg0 <= 0 || pg0 >= 0x1000 || sd0 <= 0 || sd0 >= 0x1000) {
        printf("pid_identity_probe: FAIL pgid=%d sid=%d not in vpid space (internal-tid leak)\n",
               (int)pg0, (int)sd0);
        return 1;
    }
    printf("pid_identity_probe: PASS pid=%d (==child getpid==waitpid); child getppid=%d==parent; pgid=%d sid=%d\n",
           (int)pid, (int)child_getppid, (int)pg0, (int)sd0);
    return 0;
}
