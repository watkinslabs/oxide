// /bin/sigurg_async_smoke — proves ASYNC signal delivery to a thread
// spinning in TIGHT userspace code (no syscalls). This is exactly Go's
// async-preemption mechanism: the runtime's sysmon thread tgkills
// SIGURG to a goroutine-thread busy in user code, and the kernel must
// deliver the handler when that thread next takes a timer IRQ
// (F412 Stage E async IRQ-exit delivery + Stage G cross-thread nudge).
//
// Design: the MAIN thread installs an SA_SIGINFO|SA_RESTART handler for
// SIGURG, then spins in a tight `for(;;) counter++;` loop doing NO
// syscalls. A second pthread pthread_kill()s SIGURG to the main thread
// (glibc/musl route pthread_kill→tgkill). If async delivery works, the
// handler runs mid-spin, sets `got`, and the main loop sees it + prints
// "GOT-SIGNAL" and exits 0. If async delivery is broken, the main loop
// spins forever (the signal stays pending with no syscall to ride).
//
// Expected output on a working kernel:
//   sigurg: start
//   sigurg: spinning, awaiting async SIGURG
//   sigurg: GOT-SIGNAL si_signo=16 code=...
//   sigurg: PASS
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

static int w(const char *s) { return write(1, s, strlen(s)); }

static volatile sig_atomic_t got = 0;
static volatile sig_atomic_t seen_signo = 0;

static void on_urg(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    seen_signo = si ? si->si_signo : sig;
    got = 1;
}

static pthread_t main_tid;

static void *killer(void *arg) {
    (void)arg;
    // Give the main thread time to reach its tight spin, then hammer
    // SIGURG at it until the handler fires (each pthread_kill is a
    // tgkill that sets the pending bit + Stage-G resched nudge).
    for (int i = 0; i < 2000 && !got; i++) {
        pthread_kill(main_tid, SIGURG);
        for (volatile int d = 0; d < 200000; d++) {}  // small backoff
    }
    return 0;
}

int main(void) {
    w("sigurg: start\n");
    main_tid = pthread_self();

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_urg;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGURG, &sa, 0) != 0) { w("sigurg: sigaction FAIL\n"); return 1; }

    pthread_t k;
    if (pthread_create(&k, NULL, killer, NULL) != 0) { w("sigurg: pthread_create FAIL\n"); return 1; }

    w("sigurg: spinning, awaiting async SIGURG\n");
    // Tight no-syscall spin. Only `got` (set by the async handler) gets
    // us out. A bounded cap avoids a forever-hang on a broken kernel.
    volatile uint64_t counter = 0;
    for (uint64_t i = 0; i < 200000000ULL && !got; i++) { counter++; }

    if (!got) { w("sigurg: TIMEOUT (no async delivery)\n"); return 2; }

    w("sigurg: GOT-SIGNAL signo=");
    char b[4]; int n = seen_signo;
    b[0] = '0' + (n / 10) % 10; b[1] = '0' + n % 10; b[2] = '\n'; b[3] = 0;
    write(1, b, 3);
    pthread_join(k, 0);
    w("sigurg: PASS\n");
    return 0;
}
