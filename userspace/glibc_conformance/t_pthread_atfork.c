/* pthread_atfork: prepare(LIFO) before fork, parent/child(FIFO) after. Only the
 * parent prints (child reports its handler count via exit status). vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>

static int prep, par, chld;
static void on_prepare(void) { prep++; }
static void on_parent(void)  { par++; }
static void on_child(void)   { chld++; }

int main(void) {
    pthread_atfork(on_prepare, on_parent, on_child);
    pid_t p = fork();
    if (p == 0) _exit(chld);          /* child: # of child handlers that ran */
    int st = 0; waitpid(p, &st, 0);
    int child_ran = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    printf("prepare=%d parent=%d child=%d\n", prep, par, child_ran);
    return 0;
}
