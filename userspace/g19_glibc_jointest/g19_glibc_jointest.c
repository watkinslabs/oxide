/* Diagnostic: isolate pthread_join (CHILD_CLEARTID futex wake) from the
 * mutex. Worker does NOTHING but mark + return; main joins. If g19j-join-ok
 * prints, join/CHILD_CLEARTID works → the hang is the mutex futex. If only
 * g19j-worker-ran + g19j-pre-join print, the thread-exit wake is broken. */
#include <pthread.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static int cfd;
static void mark(const char *s) { if (cfd >= 0) { ssize_t r = write(cfd, s, strlen(s)); (void)r; } }

static void *worker(void *arg) { (void)arg; mark("g19j-worker-ran\n"); return (void *)0x55; }

int main(void) {
    cfd = open("/dev/console", O_WRONLY);
    pthread_t t;
    if (pthread_create(&t, 0, worker, 0) != 0) { mark("g19j-create-FAIL\n"); return 1; }
    mark("g19j-pre-join\n");
    void *ret;
    if (pthread_join(t, &ret) == 0 && ret == (void *)0x55) mark("g19j-join-ok\n");
    mark("g19j-done\n");
    return 0;
}
