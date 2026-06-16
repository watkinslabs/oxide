/* G19: pthread on the oxide kernel — clone trampoline + per-thread TLS,
 * futex-backed mutex under contention, and pthread_join (futex wait on
 * CHILD_CLEARTID). 4 threads each bump a shared counter 1000x under a
 * mutex; correct total (4000) proves the mutex (no lost updates) and the
 * clone/join lifecycle. Markers → /dev/console (→serial). */
#include <pthread.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static int cfd;
static void mark(const char *s) { if (cfd >= 0) { ssize_t r = write(cfd, s, strlen(s)); (void)r; } }

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static volatile long counter;

static void *worker(void *arg) {
    long n = (long)arg;
    for (long i = 0; i < n; i++) { pthread_mutex_lock(&mtx); counter++; pthread_mutex_unlock(&mtx); }
    return (void *)0x1234;
}

int main(void) {
    cfd = open("/dev/console", O_WRONLY);
    pthread_t t[4];
    for (int i = 0; i < 4; i++)
        if (pthread_create(&t[i], 0, worker, (void *)1000) != 0) { mark("g19p-create-FAIL\n"); return 1; }
    mark("g19p-create-ok\n");
    int joined = 0;
    for (int i = 0; i < 4; i++) { void *ret; if (pthread_join(t[i], &ret) == 0 && ret == (void *)0x1234) joined++; }
    if (joined == 4) mark("g19p-join-ok\n");
    if (counter == 4000) mark("g19p-mutex-ok\n");
    mark("g19p-done\n");
    return 0;
}
