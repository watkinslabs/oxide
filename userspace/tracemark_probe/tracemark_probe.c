// /bin/tracemark_probe — F-series regression guard: the ftrace trace_marker
// path must be REAL, not a static placeholder. Pre-change /sys/kernel/tracing/
// {trace,trace_marker,tracing_on} were fixed StaticFileInode bytes — a write
// to trace_marker vanished and `trace` always read "# tracer: nop".
//
// Asserts the Linux contract:
//   1. write("OXIDE_MARK_42") to trace_marker → reading `trace` shows a
//      "tracing_mark_write: OXIDE_MARK_42" line (the marker was recorded +
//      rendered in ftrace format).
//   2. `echo 0 > tracing_on` then a marker write is NOT recorded (gating);
//      `echo 1 > tracing_on` re-enables and the next marker IS recorded.
//   3. `echo > trace` clears the buffer (subsequent read has no marker line).

#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define PASS "tracemark_probe: PASS\n"
static void fail(const char *why) {
    write(2, "tracemark_probe: FAIL ", 22);
    write(2, why, strlen(why));
    write(2, "\n", 1);
    _exit(1);
}

static void mark(const char *s) {
    int fd = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
    if (fd < 0) fail("open trace_marker");
    write(fd, s, strlen(s));
    close(fd);
}
static void set_on(const char *v) {
    int fd = open("/sys/kernel/tracing/tracing_on", O_WRONLY);
    if (fd < 0) fail("open tracing_on");
    write(fd, v, strlen(v));
    close(fd);
}
// Read all of `trace` into buf; return whether `needle` occurs.
static int trace_has(const char *needle) {
    int fd = open("/sys/kernel/tracing/trace", O_RDONLY);
    if (fd < 0) fail("open trace");
    static char buf[16384];
    int total = 0, n;
    while ((n = read(fd, buf + total, sizeof buf - 1 - total)) > 0) {
        total += n;
        if (total >= (int)sizeof buf - 1) break;
    }
    close(fd);
    buf[total] = 0;
    return strstr(buf, needle) != 0;
}
static void clear_trace(void) {
    int fd = open("/sys/kernel/tracing/trace", O_WRONLY | O_TRUNC);
    if (fd < 0) fail("open trace w");
    write(fd, "\n", 1);
    close(fd);
}

int main(void) {
    // (1) record + render.
    set_on("1");
    clear_trace();
    mark("OXIDE_MARK_42");
    if (!trace_has("tracing_mark_write: OXIDE_MARK_42")) fail("marker not recorded/rendered");

    // (2) gating: tracing_on=0 drops the write.
    clear_trace();
    set_on("0");
    mark("OXIDE_GATED");
    if (trace_has("OXIDE_GATED")) fail("marker recorded while tracing_on=0");
    set_on("1");
    mark("OXIDE_REENABLED");
    if (!trace_has("OXIDE_REENABLED")) fail("marker dropped after re-enable");

    // (3) clear empties the buffer.
    clear_trace();
    if (trace_has("OXIDE_REENABLED")) fail("clear did not empty the buffer");

    write(1, PASS, sizeof PASS - 1);
    return 0;
}
