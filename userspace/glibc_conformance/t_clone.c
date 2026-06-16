/* clone(2): child runs fn(arg) on its own stack, exits with fn's return. vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

static int child_fn(void *arg) { return (int)(long)arg; }

int main(void) {
    size_t sz = 256 * 1024;
    char *stack = malloc(sz);
    pid_t pid = clone(child_fn, stack + sz, SIGCHLD, (void *)(long)33);
    int st = 0;
    waitpid(pid, &st, 0);
    printf("clone_ok=%d exit=%d\n", pid > 0, WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    pid_t p2 = clone(child_fn, stack + sz, SIGCHLD, (void *)(long)0);
    int st2 = 0; waitpid(p2, &st2, 0);
    printf("clone2_exit=%d\n", WIFEXITED(st2) ? WEXITSTATUS(st2) : -1);
    free(stack);
    return 0;
}
