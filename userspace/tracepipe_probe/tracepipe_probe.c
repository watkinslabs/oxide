// /bin/tracepipe_probe — F-series guard: /sys/kernel/tracing/trace_pipe must
// be a REAL consuming ftrace reader, not a static empty placeholder.
//
// Asserts:
//   1. After writing a marker, an O_NONBLOCK read of trace_pipe returns the
//      rendered "tracing_mark_write: OXIDE_PIPE_7" event line.
//   2. trace_pipe is CONSUMING: a second O_NONBLOCK read drains to EAGAIN
//      (the record was removed, unlike `trace` which is a non-destructive
//      snapshot).
//
// Uses O_NONBLOCK so an empty read returns EAGAIN instead of blocking
// forever (the kernel parks a blocking trace_pipe read until data arrives).

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#define PASS "tracepipe_probe: PASS\n"
static void fail(const char *why) {
    write(2, "tracepipe_probe: FAIL ", 22);
    write(2, why, strlen(why));
    write(2, "\n", 1);
    _exit(1);
}

int main(void) {
    // Enable + write a marker.
    int on = open("/sys/kernel/tracing/tracing_on", O_WRONLY);
    if (on < 0) fail("open tracing_on"); write(on, "1", 1); close(on);
    int mk = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
    if (mk < 0) fail("open trace_marker"); write(mk, "OXIDE_PIPE_7", 12); close(mk);

    int fd = open("/sys/kernel/tracing/trace_pipe", O_RDONLY | O_NONBLOCK);
    if (fd < 0) fail("open trace_pipe");

    // (1) the marker streams out.
    char buf[4096];
    int n = read(fd, buf, sizeof buf - 1);
    if (n <= 0) fail("trace_pipe read returned no data");
    buf[n] = 0;
    if (!strstr(buf, "tracing_mark_write: OXIDE_PIPE_7")) fail("marker not in trace_pipe stream");

    // (2) consuming: nothing left → EAGAIN.
    errno = 0;
    int n2 = read(fd, buf, sizeof buf - 1);
    if (n2 > 0) fail("trace_pipe not consuming (data remained)");
    if (n2 < 0 && errno != EAGAIN) fail("empty trace_pipe should be EAGAIN");
    close(fd);

    write(1, PASS, sizeof PASS - 1);
    return 0;
}
