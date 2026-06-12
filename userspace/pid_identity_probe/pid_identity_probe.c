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

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) { printf("pid_identity_probe: FAIL pipe\n"); return 1; }
    pid_t parent_pid = getpid();
    pid_t pid = fork();
    if (pid < 0) { printf("pid_identity_probe: FAIL fork\n"); return 1; }
    if (pid == 0) {
        /* child: report own getpid() to the parent, then exit 42. */
        close(fds[0]);
        pid_t mine = getpid();
        ssize_t _ = write(fds[1], &mine, sizeof mine);
        (void)_;
        close(fds[1]);
        _exit(42);
    }
    /* parent */
    close(fds[1]);
    pid_t child_getpid = -1;
    if (read(fds[0], &child_getpid, sizeof child_getpid) != (ssize_t)sizeof child_getpid) {
        printf("pid_identity_probe: FAIL pipe-read\n"); return 1;
    }
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
    printf("pid_identity_probe: PASS pid=%d (== child getpid == waitpid)\n", (int)pid);
    return 0;
}
