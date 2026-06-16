/* posix_spawn: launch /bin/echo with a stdout-redirect file action; wait; read
 * it back. posix_spawnp PATH search. Exec'd host binaries get a CLEAN env (no
 * LD_LIBRARY_PATH) so they load host libs, not the test's oxide sysroot. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sched.h>
#include <string.h>

static char *CLEAN[] = { "PATH=/usr/bin:/bin", NULL };

int main(void) {
    char out[] = "/tmp/spawn_XXXXXX";
    int tfd = mkstemp(out); close(tfd);

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 1, out, O_WRONLY|O_TRUNC, 0644);

    char *argv[] = { "echo", "spawned-ok", NULL };
    pid_t pid; int status = 0;
    int rc = posix_spawn(&pid, "/bin/echo", &fa, NULL, argv, CLEAN);
    if (rc == 0) waitpid(pid, &status, 0);
    posix_spawn_file_actions_destroy(&fa);

    char buf[32] = {0};
    int rfd = open(out, O_RDONLY); ssize_t n = read(rfd, buf, sizeof buf - 1); close(rfd);
    if (n > 0 && buf[n-1] == '\n') buf[n-1] = 0;
    printf("spawn rc=%d exited=%d out=%s\n", rc, WIFEXITED(status) && WEXITSTATUS(status)==0, buf);

    pid_t pid2; int st2 = 0;
    int rc2 = posix_spawnp(&pid2, "true", NULL, NULL, (char*[]){"true",NULL}, CLEAN);
    if (rc2 == 0) waitpid(pid2, &st2, 0);
    printf("spawnp rc=%d exit0=%d\n", rc2, WIFEXITED(st2) && WEXITSTATUS(st2)==0);

    /* _np file action: addchdir_np to /tmp, then run pwd with stdout redirected. */
    char out2[] = "/tmp/spawn2_XXXXXX";
    int t2 = mkstemp(out2); close(t2);
    posix_spawn_file_actions_t fa2;
    posix_spawn_file_actions_init(&fa2);
    posix_spawn_file_actions_addchdir_np(&fa2, "/tmp");
    posix_spawn_file_actions_addopen(&fa2, 1, out2, O_WRONLY|O_TRUNC, 0644);
    pid_t pid3; int st3 = 0;
    int rc3 = posix_spawn(&pid3, "/bin/pwd", &fa2, NULL, (char*[]){"pwd",NULL}, CLEAN);
    if (rc3 == 0) waitpid(pid3, &st3, 0);
    posix_spawn_file_actions_destroy(&fa2);
    char cw[64] = {0};
    int cf = open(out2, O_RDONLY); ssize_t cn = read(cf, cw, sizeof cw - 1); close(cf);
    if (cn > 0 && cw[cn-1] == '\n') cw[cn-1] = 0;
    printf("chdir_np rc=%d cwd=%s\n", rc3, cw);

    /* spawnattr getter round-trip (pure, no spawn). */
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETPGROUP|POSIX_SPAWN_SETSCHEDULER);
    posix_spawnattr_setpgroup(&at, 4242);
    posix_spawnattr_setschedpolicy(&at, SCHED_RR);
    struct sched_param sp = { .sched_priority = 7 }; posix_spawnattr_setschedparam(&at, &sp);
    short gf = 0; int gpg = 0, gpol = 0; struct sched_param gsp = {0};
    posix_spawnattr_getflags(&at, &gf);
    posix_spawnattr_getpgroup(&at, &gpg);
    posix_spawnattr_getschedpolicy(&at, &gpol);
    posix_spawnattr_getschedparam(&at, &gsp);
    posix_spawnattr_destroy(&at);
    printf("attr flags=0x%x pg=%d pol=%d prio=%d\n", gf & 0x3f, gpg, gpol, gsp.sched_priority);

    unlink(out); unlink(out2);
    return 0;
}
