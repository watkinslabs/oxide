// /bin/tracesys_probe — §2.12 guard: the sys_enter / sys_exit static
// tracepoints must record real syscalls into the per-CPU ring.
//
// Asserts:
//   1. available_events lists syscalls:sys_enter and syscalls:sys_exit.
//   2. enable sys_enter → after syscalls, `trace` has "sys_enter:" lines.
//   3. enable sys_exit  → after syscalls, `trace` has "sys_exit:" lines.
//   4. disabling both stops new records.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define PASS "tracesys_probe: PASS\n"
static void fail(const char *why) {
    write(2, "tracesys_probe: FAIL ", 21);
    write(2, why, strlen(why));
    write(2, "\n", 1);
    _exit(1);
}
#define ENTER "/sys/kernel/tracing/events/syscalls/sys_enter/enable"
#define EXIT  "/sys/kernel/tracing/events/syscalls/sys_exit/enable"

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
// Generate a few easily-identified syscalls.
static void do_syscalls(void) { for (int i = 0; i < 20; i++) { (void)getpid(); (void)getuid(); } }

int main(void) {
    // (1) advertised.
    {
        int fd = open("/sys/kernel/tracing/available_events", O_RDONLY);
        if (fd < 0) fail("open available_events");
        char b[256]; int n = read(fd, b, sizeof b - 1); close(fd);
        if (n <= 0) fail("available_events empty"); b[n] = 0;
        if (!strstr(b, "syscalls:sys_enter")) fail("sys_enter not advertised");
        if (!strstr(b, "syscalls:sys_exit"))  fail("sys_exit not advertised");
    }

    // (2) sys_enter records.
    wr(ENTER, "1");
    wr("/sys/kernel/tracing/trace", "0");
    do_syscalls();
    if (!trace_has("sys_enter:")) fail("no sys_enter records");
    wr(ENTER, "0");

    // (3) sys_exit records.
    wr(EXIT, "1");
    wr("/sys/kernel/tracing/trace", "0");
    do_syscalls();
    if (!trace_has("sys_exit:")) fail("no sys_exit records");
    wr(EXIT, "0");

    // (4) both off → no new records.
    wr("/sys/kernel/tracing/trace", "0");
    do_syscalls();
    if (trace_has("sys_enter:") || trace_has("sys_exit:")) fail("records after disable");

    write(1, PASS, sizeof PASS - 1);
    return 0;
}
