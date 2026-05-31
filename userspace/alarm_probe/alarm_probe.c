// /bin/alarm_probe — B20 regression guard: alarm(2)/SIGALRM must wake a
// task parked in a blocking read(). A read() on an empty pipe whose write
// end stays open blocks indefinitely; with alarm(1)+SIGALRM handler the
// kernel must post SIGALRM and wake the parked reader so read returns
// -1/EINTR. Pre-B20 the alarm deadline was only checked at syscall-return
// tail, never for a task that issues no further syscalls — so this read
// hung forever. Fixed by servicing alarm_ns in the periodic timer-wake
// scanner (sched::live::tick_wake_expired).

#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#define PASS "alarm_probe: PASS\n"
#define FAIL "alarm_probe: FAIL\n"

static volatile int got_alrm = 0;
static void on_alrm(int s) { (void)s; got_alrm++; }

int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alrm;            // no SA_RESTART: read must surface EINTR
    sigaction(SIGALRM, &sa, 0);

    int p[2];
    if (pipe(p) < 0) { write(1, FAIL, sizeof FAIL - 1); return 1; }
    // Keep p[1] open so the read blocks (writers != 0, no EOF).

    alarm(1);
    char b[8];
    int n = read(p[0], b, sizeof b);   // must block, then be interrupted
    int e = errno;

    if (n < 0 && e == EINTR && got_alrm == 1) {
        write(1, PASS, sizeof PASS - 1); return 0;
    }
    write(1, FAIL, sizeof FAIL - 1);
    return 1;
}
