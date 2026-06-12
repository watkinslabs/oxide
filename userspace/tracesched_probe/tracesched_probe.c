// /bin/tracesched_probe — §2.12 guard: the sched_switch static tracepoint
// must record real context switches into the per-CPU ring and render them in
// `trace`. Enabling events/sched/sched_switch/enable installs the scheduler
// hook; disabling clears it.
//
// Asserts:
//   1. available_events lists "sched:sched_switch".
//   2. After enabling the event and yielding (usleep → context switches),
//      `trace` contains "sched_switch:" lines.
//   3. After disabling + clearing, a fresh yield produces NO new sched_switch
//      records (the hook was uninstalled).

#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define PASS "tracesched_probe: PASS\n"
static void fail(const char *why) {
    write(2, "tracesched_probe: FAIL ", 23);
    write(2, why, strlen(why));
    write(2, "\n", 1);
    _exit(1);
}

#define ENABLE "/sys/kernel/tracing/events/sched/sched_switch/enable"

static void wr(const char *path, const char *v) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) fail("open-w");
    write(fd, v, strlen(v));
    close(fd);
}
static int trace_has(const char *needle) {
    int fd = open("/sys/kernel/tracing/trace", O_RDONLY);
    if (fd < 0) fail("open trace");
    static char buf[65536];
    int total = 0, n;
    while ((n = read(fd, buf + total, sizeof buf - 1 - total)) > 0) {
        total += n;
        if (total >= (int)sizeof buf - 1) break;
    }
    close(fd);
    buf[total] = 0;
    return strstr(buf, needle) != 0;
}
static void yield_a_bit(void) { for (int i = 0; i < 30; i++) usleep(3000); }

int main(void) {
    // (1) available_events lists the tracepoint.
    {
        int fd = open("/sys/kernel/tracing/available_events", O_RDONLY);
        if (fd < 0) fail("open available_events");
        char b[256]; int n = read(fd, b, sizeof b - 1); close(fd);
        if (n <= 0) fail("available_events empty");
        b[n] = 0;
        if (!strstr(b, "sched:sched_switch")) fail("sched:sched_switch not advertised");
    }

    // (2) enable → yield → sched_switch records appear.
    wr(ENABLE, "1");
    wr("/sys/kernel/tracing/trace", "0");   // clear
    yield_a_bit();
    if (!trace_has("sched_switch:")) fail("no sched_switch records after enable");

    // (3) disable → clear → no new records.
    wr(ENABLE, "0");
    wr("/sys/kernel/tracing/trace", "0");
    yield_a_bit();
    if (trace_has("sched_switch:")) fail("sched_switch still recording after disable");

    write(1, PASS, sizeof PASS - 1);
    return 0;
}
