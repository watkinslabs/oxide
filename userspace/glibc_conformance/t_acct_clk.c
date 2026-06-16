/* acct (priv→fail), clock_getcpuclockid, execvpe (PATH + direct). vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>

int main(void) {
    /* acct as non-root (or bad path) fails -> identical -1 on host + ours */
    printf("acct_fail=%d\n", acct("/tmp/no_such_acct_file") < 0);

    clockid_t clk;
    int r = clock_getcpuclockid(getpid(), &clk);
    struct timespec ts;
    printf("getcpuclockid=%d clock_ok=%d\n", r, clock_gettime(clk, &ts) == 0);

    /* execvpe via PATH with a clean envp (so the host bin loads host libc) */
    pid_t p = fork();
    if (p == 0) {
        char *av[] = { "true", NULL };
        char *ev[] = { "PATH=/bin:/usr/bin", NULL };
        execvpe("true", av, ev);
        _exit(127);
    }
    int st = 0; waitpid(p, &st, 0);
    printf("execvpe_path=%d\n", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    pid_t p2 = fork();
    if (p2 == 0) {
        char *av[] = { "false", NULL };
        char *ev[] = { "PATH=/bin:/usr/bin", NULL };
        execvpe("/usr/bin/false", av, ev);  /* direct (has '/') */
        _exit(127);
    }
    int st2 = 0; waitpid(p2, &st2, 0);
    printf("execvpe_direct=%d\n", WIFEXITED(st2) && WEXITSTATUS(st2) == 1);
    return 0;
}
