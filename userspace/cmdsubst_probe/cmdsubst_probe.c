// /bin/cmdsubst_probe — kernel pipe-capture correctness regression.
// Reproduces the two shapes a shell uses for `$(cmd)`:
//   plain : parent pipe()s, forks a child whose stdout is the pipe,
//           child execs echo, parent reads to EOF.
//   nested: mimics `$(echo one; echo two)` — a "subshell" child holds
//           the write end and sequentially forks two echo children,
//           then exits; grandparent reads to EOF (exercises shared
//           write-end refcount across nested fork + process exit).
// Both must capture the full output. The kernel passes both; bash's
// own `$()` does not (tracked separately as a bash-specific bug — the
// kernel pipe path is proven correct by this probe).

#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

// Capture WITH a SIGCHLD handler installed (as every shell does).
// When the comsub child exits, SIGCHLD is delivered to the parent
// mid-read; if signal delivery corrupts the interrupted register/
// stack state, the captured bytes are lost — reproducing the
// all-shells `$()`-empty symptom that the no-handler captures miss.
static volatile int chld = 0;
static void on_chld(int s) { (void)s; chld++; }
static int sigchld_capture(char *out, int cap) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_chld; sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, 0);
    int p[2];
    if (pipe(p) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        dup2(p[1], 1); close(p[0]); close(p[1]);
        execl("/bin/echo", "echo", "SIGCHLD_OK", (char*)0);
        _exit(127);
    }
    close(p[1]);
    int t = 0, n;
    while (t < cap - 1 && (n = read(p[0], out + t, cap - 1 - t)) > 0) t += n;
    if (t < 0) t = 0;
    out[t] = '\0';
    close(p[0]); int s; waitpid(pid, &s, 0);
    return t;
}

#define PASS "cmdsubst_probe: PASS\n"
#define FAIL "cmdsubst_probe: FAIL\n"

// Single child writes "PROBE_OK"; parent must read all 9 bytes.
static int plain(void) {
    int p[2];
    if (pipe(p) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        dup2(p[1], 1); close(p[0]); close(p[1]);
        execl("/bin/echo", "echo", "PROBE_OK", (char*)0);
        _exit(127);
    }
    close(p[1]);
    char b[64]; int t = 0, n;
    while (t < (int)sizeof b - 1 && (n = read(p[0], b + t, sizeof b - 1 - t)) > 0) t += n;
    b[t < 0 ? 0 : t] = '\0';
    close(p[0]); int s; waitpid(pid, &s, 0);
    return (t == 9 && strncmp(b, "PROBE_OK", 8) == 0) ? 0 : -1;
}

// Subshell holds the write end across two sequential echo children.
static int nested(void) {
    int p[2];
    if (pipe(p) < 0) return -1;
    pid_t sub = fork();
    if (sub < 0) return -1;
    if (sub == 0) {
        dup2(p[1], 1); close(p[0]); close(p[1]);
        for (int i = 0; i < 2; i++) {
            pid_t c = fork();
            if (c == 0) { execl("/bin/echo", "echo", i ? "two" : "one", (char*)0); _exit(127); }
            int s; waitpid(c, &s, 0);
        }
        _exit(0);
    }
    close(p[1]);
    char b[64]; int t = 0, n;
    while (t < (int)sizeof b - 1 && (n = read(p[0], b + t, sizeof b - 1 - t)) > 0) t += n;
    b[t < 0 ? 0 : t] = '\0';
    close(p[0]); int s; waitpid(sub, &s, 0);
    return (strcmp(b, "one\ntwo\n") == 0) ? 0 : -1;
}

int main(void) {
    // The sigchld capture is the regression guard for the signal-
    // return-value bug: a SIGCHLD handler interrupting the comsub read
    // must NOT lose the read's return value.
    char sc[64];
    int scn = sigchld_capture(sc, sizeof sc);
    int sigchld_ok = (scn == 11 && strncmp(sc, "SIGCHLD_OK\n", 11) == 0);
    if (plain() == 0 && nested() == 0 && sigchld_ok) {
        write(1, PASS, sizeof PASS - 1); return 0;
    }
    write(1, FAIL, sizeof FAIL - 1);
    return 1;
}
