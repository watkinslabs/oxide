// /bin/cputime_probe — G3 regression guard: getrusage(2)/times(2) must
// report REAL per-task CPU time, not wall-clock/zero. Pre-G3 ru_utime was
// wall-clock (monotonic_ns - spawn_ns), ru_stime + tms_stime were 0, and
// tms_utime was wall-clock. This burns CPU in a tight USER-mode loop (no
// syscalls in the hot path, so it accrues utime) until times() advances by
// several CLK_TCK ticks, then asserts getrusage(RUSAGE_SELF).ru_utime > 0
// and times().tms_utime > 0. Tick-sampled accounting charges the timer-IRQ
// interval to the interrupted task, so a CPU-bound user loop accrues utime.

#include <unistd.h>
#include <string.h>
#include <sys/times.h>
#include <sys/resource.h>

#define PASS "cputime_probe: PASS\n"
#define FAIL "cputime_probe: FAIL\n"

int main(void) {
    struct tms t0, t1;
    clock_t start = times(&t0);

    // Busy-loop in user mode until wall-clock (times() return) advances by
    // >= 5 ticks, so several timer IRQs land on this task. `volatile` sink
    // keeps the compiler from eliding the loop; no syscalls in the hot path.
    volatile unsigned long sink = 0;
    clock_t now = start;
    do {
        for (int i = 0; i < 200000; i++) sink += (unsigned long)i * 2654435761u;
        now = times(&t1);
    } while (now != (clock_t)-1 && (now - start) < 5);

    struct rusage ru;
    memset(&ru, 0, sizeof ru);
    getrusage(RUSAGE_SELF, &ru);

    long ru_us = (long)ru.ru_utime.tv_sec * 1000000L + (long)ru.ru_utime.tv_usec;

    // Both surfaces must show non-zero user CPU time after a CPU-bound loop.
    if (ru_us > 0 && t1.tms_utime > 0) {
        write(1, PASS, sizeof PASS - 1);
        return 0;
    }
    write(1, FAIL, sizeof FAIL - 1);
    (void)sink;
    return 1;
}
