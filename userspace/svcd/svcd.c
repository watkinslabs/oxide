// /sbin/svcd — minimal service supervisor for oxide. Mirrors
// the Rust `svc` crate's state machine but compiled native into
// the userspace binary so it can run as a child of /init (or
// directly as PID 1 if init exec()s svcd).
//
// Reads /etc/svc/*.service unit files, walks them in spawn order
// (Idle → Running), reaps via wait4, applies Restart= policy
// with a 5-iteration backoff. Subset matches Rust crate:
//   ExecStart=, Type= (simple/oneshot), Restart= (no/always/on-failure),
//   After=
//
// v1 limits (lifted later):
//   - reads up to 16 unit files, total 32 KB
//   - argv up to 8 tokens per unit
//   - no per-service log streams (writes to its own stdout/stderr)
//   - no cgroup isolation (P15-04+)
//   - flat dependency model: After= sorted via insertion order;
//     cycles cause unstarted units (no error reporting yet)

#include <sys/syscall.h>
#include <stdint.h>

#define O_RDONLY 0
#define AT_FDCWD -100
#define MAX_UNITS 16
#define MAX_ARGV 8
#define MAX_NAME 64
#define MAX_LINE 256
#define UNIT_BUF 4096

static long sc1(long n, long a) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx","r11","memory"); return r;
}
static long sc3(long n, long a, long b, long c) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory"); return r;
}
static long sc4(long n, long a, long b, long c, long d) {
    long r; register long r10 __asm__("r10") = d;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx","r11","memory");
    return r;
}

static long mlen(const char* s) { long n=0; while (s[n]) n++; return n; }
static void wstr(int fd, const char* s) { sc3(SYS_write, fd, (long)s, mlen(s)); }
static int  streq(const char* a, const char* b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}
static int strpfx(const char* s, const char* p) {
    while (*p) { if (*s != *p) return 0; s++; p++; }
    return 1;
}

enum { TY_SIMPLE = 0, TY_ONESHOT = 1, TY_FORKING = 2 };
enum { R_NO = 0, R_ALWAYS = 1, R_ONFAIL = 2 };
enum { ST_IDLE = 0, ST_RUNNING = 1, ST_STOPPED = 2, ST_FAILED = 3 };

typedef struct {
    char name[MAX_NAME];
    char path[64];
    char argv_buf[MAX_LINE];
    char* argv[MAX_ARGV + 1];
    int  argc;
    int  type;
    int  restart;
    int  state;
    long pid;
    int  last_status;
    long restart_at_tick;
    char after[MAX_NAME];
} Unit;

static Unit  units[MAX_UNITS];
static int   nunits = 0;
static char  unit_buf[UNIT_BUF];

// Read a whole file into buf. Returns bytes read or -1 on error.
static long read_file(const char* path, char* buf, long cap) {
    long fd = sc4(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0);
    if (fd < 0) return -1;
    long t = 0;
    while (t < cap - 1) {
        long n = sc3(SYS_read, fd, (long)(buf + t), cap - 1 - t);
        if (n <= 0) break; t += n;
    }
    sc1(SYS_close, fd);
    buf[t] = 0;
    return t;
}

// Trim leading + trailing whitespace in place, returning new start.
static char* trim(char* s) {
    while (*s == ' ' || *s == '\t') s++;
    long n = mlen(s);
    while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\n' || s[n-1] == '\r')) {
        s[--n] = 0;
    }
    return s;
}

// Tokenize argv from a single line into u->argv. Stores in argv_buf.
static void set_argv(Unit* u, const char* line) {
    long len = mlen(line);
    if (len >= MAX_LINE) len = MAX_LINE - 1;
    for (long i = 0; i < len; i++) u->argv_buf[i] = line[i];
    u->argv_buf[len] = 0;
    u->argc = 0;
    char* p = u->argv_buf;
    while (*p && u->argc < MAX_ARGV) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        u->argv[u->argc++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) { *p = 0; p++; }
    }
    u->argv[u->argc] = 0;
}

static int parse_unit(const char* name, const char* body, Unit* u) {
    long nl = mlen(name); if (nl >= MAX_NAME) return -1;
    for (long i = 0; i < nl; i++) u->name[i] = name[i]; u->name[nl] = 0;
    u->type = TY_SIMPLE;
    u->restart = R_NO;
    u->state = ST_IDLE;
    u->pid = 0;
    u->last_status = 0;
    u->restart_at_tick = 0;
    u->argc = 0;
    u->after[0] = 0;
    char section[16] = {0};
    char line[MAX_LINE];
    long i = 0, ll = mlen(body);
    while (i < ll) {
        long s = i;
        while (i < ll && body[i] != '\n') i++;
        long lnlen = i - s;
        if (lnlen >= MAX_LINE) lnlen = MAX_LINE - 1;
        for (long k = 0; k < lnlen; k++) line[k] = body[s + k];
        line[lnlen] = 0;
        if (i < ll) i++;
        char* t = trim(line);
        if (!*t || t[0] == '#' || t[0] == ';') continue;
        if (t[0] == '[') {
            long m = mlen(t);
            if (m >= 2 && t[m-1] == ']') {
                t[m-1] = 0;
                long sl = m - 2; if (sl >= (long)sizeof(section)) sl = sizeof(section) - 1;
                for (long k = 0; k < sl; k++) section[k] = t[1 + k];
                section[sl] = 0;
            }
            continue;
        }
        char* eq = 0;
        for (char* p = t; *p; p++) if (*p == '=') { eq = p; break; }
        if (!eq) continue;
        *eq = 0;
        char* k = trim(t);
        char* v = trim(eq + 1);
        if (streq(section, "Service")) {
            if (streq(k, "ExecStart")) set_argv(u, v);
            else if (streq(k, "Type")) {
                if (streq(v, "simple"))       u->type = TY_SIMPLE;
                else if (streq(v, "oneshot")) u->type = TY_ONESHOT;
                else if (streq(v, "forking")) u->type = TY_FORKING;
            }
            else if (streq(k, "Restart")) {
                if (streq(v, "no"))              u->restart = R_NO;
                else if (streq(v, "always"))     u->restart = R_ALWAYS;
                else if (streq(v, "on-failure")) u->restart = R_ONFAIL;
            }
        } else if (streq(section, "Unit")) {
            if (streq(k, "After")) {
                long vl = mlen(v); if (vl >= MAX_NAME) vl = MAX_NAME - 1;
                for (long m = 0; m < vl; m++) u->after[m] = v[m];
                u->after[vl] = 0;
            }
        }
    }
    if ((u->type == TY_SIMPLE || u->type == TY_FORKING) && u->argc == 0) return -1;
    return 0;
}

// Look up a unit by name; returns index or -1.
static int find_unit(const char* name) {
    for (int i = 0; i < nunits; i++) if (streq(units[i].name, name)) return i;
    return -1;
}

// Are this unit's deps satisfied? Unknown deps assumed up.
static int deps_ok(const Unit* u) {
    if (!u->after[0]) return 1;
    int idx = find_unit(u->after);
    if (idx < 0) return 1; // external dep
    int s = units[idx].state;
    return s == ST_RUNNING || s == ST_STOPPED;
}

static long g_tick = 0;

// Spawn one unit if eligible. Returns 1 if it spawned.
static int try_spawn(Unit* u) {
    int eligible;
    if (u->state == ST_IDLE) eligible = 1;
    else if (u->state == ST_FAILED) {
        if ((u->restart == R_ALWAYS || u->restart == R_ONFAIL)
            && g_tick >= u->restart_at_tick) eligible = 1;
        else eligible = 0;
    } else eligible = 0;
    if (!eligible) return 0;
    if (!deps_ok(u)) return 0;

    long pid;
    __asm__ volatile ("syscall" : "=a"(pid) : "0"((long)SYS_fork), "D"(0) : "rcx","r11","memory");
    if (pid == 0) {
        char* envp[1] = {0};
        sc4(SYS_execve, (long)u->argv[0], (long)u->argv, (long)envp, 0);
        wstr(2, "svcd: exec failed: ");
        wstr(2, u->name);
        wstr(2, "\n");
        sc1(SYS_exit, 127);
        __builtin_unreachable();
    }
    u->pid = pid;
    u->state = ST_RUNNING;
    u->restart_at_tick = 0;
    return 1;
}

// Returns 1 if any state changed.
static int reap_one(int blocking) {
    int status = 0;
    long flags = blocking ? 0 : 1; // WNOHANG = 1
    long r;
    register long r10 __asm__("r10") = 0;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_wait4), "D"(-1), "S"((long)&status), "d"(flags), "r"(r10)
        : "rcx","r11","memory");
    if (r <= 0) return 0;
    int code = status & 0xff;
    int success = (code == 0);
    for (int i = 0; i < nunits; i++) {
        if (units[i].pid == r) {
            units[i].pid = 0;
            units[i].last_status = code;
            if (units[i].type == TY_ONESHOT && success) {
                units[i].state = ST_STOPPED;
            } else {
                if (units[i].restart == R_NO) {
                    units[i].state = success ? ST_STOPPED : ST_FAILED;
                } else if (units[i].restart == R_ALWAYS
                       || (units[i].restart == R_ONFAIL && !success)) {
                    units[i].state = ST_FAILED;
                    units[i].restart_at_tick = g_tick + 5;
                } else {
                    units[i].state = ST_STOPPED;
                }
            }
            return 1;
        }
    }
    return 0;
}

// Sweep: try to spawn every eligible unit.
static void sweep_spawns(void) {
    for (int round = 0; round < nunits + 2; round++) {
        int changed = 0;
        for (int i = 0; i < nunits; i++) {
            if (try_spawn(&units[i])) changed = 1;
        }
        if (!changed) break;
    }
}

static int any_alive(void) {
    for (int i = 0; i < nunits; i++) {
        if (units[i].state == ST_RUNNING) return 1;
        if (units[i].state == ST_FAILED &&
            (units[i].restart == R_ALWAYS || units[i].restart == R_ONFAIL)) return 1;
        if (units[i].state == ST_IDLE) return 1;
    }
    return 0;
}

// Hard-coded unit list. v1: caller bakes in unit names. Future
// versions read /etc/svc/*.service via a directory walker once we
// have getdents glue in userspace.
static const char* UNITS[] = {
    "/etc/svc/sshd.service",
    "/etc/svc/getty.service",
    0,
};

static void load_units(void) {
    for (int i = 0; UNITS[i]; i++) {
        if (nunits >= MAX_UNITS) break;
        long n = read_file(UNITS[i], unit_buf, sizeof(unit_buf));
        if (n <= 0) continue;
        // Derive unit name from basename.
        const char* full = UNITS[i];
        const char* base = full;
        for (const char* p = full; *p; p++) if (*p == '/') base = p + 1;
        if (parse_unit(base, unit_buf, &units[nunits]) == 0) nunits++;
    }
}

void _start(void) {
    wstr(1, "svcd: starting\n");
    load_units();

    if (nunits == 0) {
        wstr(2, "svcd: no units\n");
        sc1(SYS_exit, 1);
        __builtin_unreachable();
    }

    // Main loop: spawn what's ready, reap what's exited, advance tick.
    while (any_alive()) {
        sweep_spawns();
        // Block on at least one wait4 to avoid spin.
        if (!reap_one(1)) break;
        // Drain any other completions non-blocking.
        while (reap_one(0)) {}
        g_tick++;
    }

    wstr(1, "svcd: all units terminal\n");
    sc1(SYS_exit, 0);
    __builtin_unreachable();
}
