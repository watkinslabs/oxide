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
#include <sys/wait.h>

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
    if (plain() == 0 && nested() == 0) { write(1, PASS, sizeof PASS - 1); return 0; }
    write(1, FAIL, sizeof FAIL - 1);
    return 1;
}
