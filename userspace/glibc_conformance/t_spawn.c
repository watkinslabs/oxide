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

    unlink(out);
    return 0;
}
