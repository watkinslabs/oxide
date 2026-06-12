// /bin/fanotify_perm_probe — §2.13 guard: fanotify FAN_OPEN_PERM must really
// block the opening task until a daemon writes a struct fanotify_response,
// and honour ALLOW vs DENY.
//
// Two rounds (fork each): the CHILD open()s a FAN_OPEN_PERM-marked file, which
// blocks in the kernel; the PARENT (daemon) blocking-read()s the perm event
// and writes the verdict.
//   round 1 ALLOW → child open() succeeds.
//   round 2 DENY  → child open() fails with EACCES.
//
// A SIGALRM watchdog turns any unexpected hang (a perm event that never
// unblocks) into FAIL rather than wedging the boot smoke.

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/fanotify.h>
#include <sys/wait.h>

#define PASS "fanotify_perm_probe: PASS\n"
static void fail(const char *why) {
    write(2, "fanotify_perm_probe: FAIL ", 26);
    write(2, why, strlen(why));
    write(2, "\n", 1);
    _exit(1);
}
static void on_alrm(int s) { (void)s; fail("watchdog (perm event never unblocked)"); }

#define TARGET "/tmp/fanotify_perm_target"

// One round: fork a child that opens TARGET (blocking on the perm event);
// the parent delivers `verdict`. Returns the child's open outcome via exit:
// child exits 0 if its open matched `expect_ok` (opened vs EACCES-denied).
static int round(int fan, unsigned verdict, int expect_ok) {
    pid_t pid = fork();
    if (pid < 0) fail("fork");
    if (pid == 0) {
        errno = 0;
        int f = open(TARGET, O_RDONLY);
        int ok = (f >= 0);
        if (ok) close(f);
        // child succeeds iff its observed outcome matches expectation.
        if (ok == expect_ok && (ok || errno == EACCES)) _exit(0);
        _exit(2);
    }
    // Parent = daemon: block-read the perm event, then answer.
    struct fanotify_event_metadata meta;
    ssize_t n = read(fan, &meta, sizeof meta);
    if (n < (ssize_t)FAN_EVENT_METADATA_LEN) fail("daemon perm read");
    if (!(meta.mask & FAN_OPEN_PERM)) fail("event missing FAN_OPEN_PERM");
    if (meta.fd < 0) fail("perm event has no object fd");
    struct fanotify_response resp = { .fd = meta.fd, .response = verdict };
    if (write(fan, &resp, sizeof resp) != (ssize_t)sizeof resp) fail("write response");
    close(meta.fd);
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) fail("waitpid");
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alrm; sigaction(SIGALRM, &sa, 0);
    alarm(10);

    int tf = open(TARGET, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (tf < 0) fail("create target");
    write(tf, "perm", 4); close(tf);

    int fan = fanotify_init(FAN_CLASS_CONTENT, O_RDONLY);
    if (fan < 0) fail("fanotify_init");
    if (fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, TARGET) != 0)
        fail("fanotify_mark FAN_OPEN_PERM");

    if (!round(fan, FAN_ALLOW, /*expect_ok=*/1)) fail("ALLOW did not permit open");
    if (!round(fan, FAN_DENY,  /*expect_ok=*/0)) fail("DENY did not block open with EACCES");

    alarm(0);
    write(1, PASS, sizeof PASS - 1);
    return 0;
}
