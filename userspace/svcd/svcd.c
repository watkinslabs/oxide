// /sbin/svcd — minimal service supervisor for oxide.
// Reads /etc/svc/*.service unit files; spawns + reaps via fork/wait4.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/wait.h>
#include <stdint.h>

#define MAX_UNITS 16
#define MAX_ARGV 8
#define MAX_NAME 64
#define MAX_LINE 256
#define UNIT_BUF 4096

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

static long read_file_(const char* path, char* buf, long cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    long t = 0;
    while (t < cap - 1) {
        ssize_t n = read(fd, buf + t, cap - 1 - t);
        if (n <= 0) break; t += n;
    }
    close(fd);
    buf[t] = 0;
    return t;
}

static char* trim(char* s) {
    while (*s == ' ' || *s == '\t') s++;
    long n = strlen(s);
    while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\n' || s[n-1] == '\r')) {
        s[--n] = 0;
    }
    return s;
}

static void set_argv(Unit* u, const char* line) {
    long len = strlen(line);
    if (len >= MAX_LINE) len = MAX_LINE - 1;
    memcpy(u->argv_buf, line, len);
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
    long nl = strlen(name); if (nl >= MAX_NAME) return -1;
    memcpy(u->name, name, nl); u->name[nl] = 0;
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
    long i = 0, ll = strlen(body);
    while (i < ll) {
        long s = i;
        while (i < ll && body[i] != '\n') i++;
        long lnlen = i - s;
        if (lnlen >= MAX_LINE) lnlen = MAX_LINE - 1;
        memcpy(line, body + s, lnlen);
        line[lnlen] = 0;
        if (i < ll) i++;
        char* t = trim(line);
        if (!*t || t[0] == '#' || t[0] == ';') continue;
        if (t[0] == '[') {
            long m = strlen(t);
            if (m >= 2 && t[m-1] == ']') {
                t[m-1] = 0;
                long sl = m - 2; if (sl >= (long)sizeof(section)) sl = sizeof(section) - 1;
                memcpy(section, t + 1, sl);
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
        if (strcmp(section, "Service") == 0) {
            if (strcmp(k, "ExecStart") == 0) set_argv(u, v);
            else if (strcmp(k, "Type") == 0) {
                if (strcmp(v, "simple") == 0)       u->type = TY_SIMPLE;
                else if (strcmp(v, "oneshot") == 0) u->type = TY_ONESHOT;
                else if (strcmp(v, "forking") == 0) u->type = TY_FORKING;
            }
            else if (strcmp(k, "Restart") == 0) {
                if (strcmp(v, "no") == 0)              u->restart = R_NO;
                else if (strcmp(v, "always") == 0)     u->restart = R_ALWAYS;
                else if (strcmp(v, "on-failure") == 0) u->restart = R_ONFAIL;
            }
        } else if (strcmp(section, "Unit") == 0) {
            if (strcmp(k, "After") == 0) {
                long vl = strlen(v); if (vl >= MAX_NAME) vl = MAX_NAME - 1;
                memcpy(u->after, v, vl);
                u->after[vl] = 0;
            }
        }
    }
    if ((u->type == TY_SIMPLE || u->type == TY_FORKING) && u->argc == 0) return -1;
    return 0;
}

static int find_unit(const char* name) {
    for (int i = 0; i < nunits; i++) if (strcmp(units[i].name, name) == 0) return i;
    return -1;
}

static int deps_ok(const Unit* u) {
    if (!u->after[0]) return 1;
    int idx = find_unit(u->after);
    if (idx < 0) return 1;
    int s = units[idx].state;
    return s == ST_RUNNING || s == ST_STOPPED;
}

static long g_tick = 0;

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

    pid_t pid = fork();
    if (pid == 0) {
        char* envp[1] = {0};
        write(1, "svcd-child: exec ", 17);
        if (u->argv[0]) write(1, u->argv[0], strlen(u->argv[0]));
        else            write(1, "<NULL>", 6);
        write(1, " (", 2);
        write(1, u->name, strlen(u->name));
        write(1, ")\n", 2);
        execve(u->argv[0], u->argv, envp);
        write(2, "svcd: exec failed: ", 19);
        write(2, u->name, strlen(u->name));
        write(2, "\n", 1);
        _exit(127);
    }
    u->pid = pid;
    u->state = ST_RUNNING;
    u->restart_at_tick = 0;
    return 1;
}

static int reap_one(int blocking) {
    int status = 0;
    int flags = blocking ? 0 : WNOHANG;
    pid_t r = waitpid(-1, &status, flags);
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

static const char* UNITS[] = {
    "/etc/svc/sshd.service",
    "/etc/svc/getty.service",
    0,
};

static void load_units(void) {
    for (int i = 0; UNITS[i]; i++) {
        if (nunits >= MAX_UNITS) break;
        long n = read_file_(UNITS[i], unit_buf, sizeof(unit_buf));
        if (n <= 0) continue;
        const char* full = UNITS[i];
        const char* base = full;
        for (const char* p = full; *p; p++) if (*p == '/') base = p + 1;
        if (parse_unit(base, unit_buf, &units[nunits]) == 0) nunits++;
    }
}

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    write(1, "svcd: starting\n", 15);
    load_units();

    if (nunits == 0) {
        write(2, "svcd: no units\n", 15);
        return 1;
    }

    while (any_alive()) {
        sweep_spawns();
        if (!reap_one(1)) break;
        while (reap_one(0)) {}
        g_tick++;
    }

    write(1, "svcd: all units terminal\n", 25);
    return 0;
}
