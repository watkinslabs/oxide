#include "probe.h"

volatile sig_atomic_t g_sig_count = 0;

void out(const char *area, const char *test, const char *fmt, ...) {
    va_list ap;
    printf("wdiff|%s|%s|", area, test);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

const char *errno_name(int err) {
    switch (err) {
    case 0: return "OK";
    case EACCES: return "EACCES";
    case EAGAIN: return "EAGAIN";
    case EBADF: return "EBADF";
    case EBUSY: return "EBUSY";
    case ECONNREFUSED: return "ECONNREFUSED";
    case EEXIST: return "EEXIST";
    case EFAULT: return "EFAULT";
    case EINTR: return "EINTR";
    case EINVAL: return "EINVAL";
    case EMSGSIZE: return "EMSGSIZE";
    case ENODEV: return "ENODEV";
    case ENOENT: return "ENOENT";
    case ENOMEM: return "ENOMEM";
    case ENOSYS: return "ENOSYS";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case EPERM: return "EPERM";
    case EPIPE: return "EPIPE";
    case ERANGE: return "ERANGE";
    case ETIMEDOUT: return "ETIMEDOUT";
    default: return "OTHER";
    }
}

static void on_sig(int s) { (void)s; g_sig_count++; }

int install_handler(int sig, int restart) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sigemptyset(&sa.sa_mask);
    /* The `eintr` mutant strips SA_RESTART everywhere: it turns every
     * "must resume" record into a "failed with EINTR" record, which is
     * exactly the pre-campaign kernel behaviour. */
    /* `restartall` is the mirror mutant: it forces SA_RESTART onto the
     * cases that must report EINTR, so those records are falsifiable too. */
    if ((restart && !mutant("eintr")) || mutant("restartall")) sa.sa_flags = SA_RESTART;
    g_sig_count = 0;
    return sigaction(sig, &sa, NULL);
}

void arm_timer_ms(unsigned ms) {
    struct itimerval it;
    /* `nosig` drops the mid-wait interrupt (never the guards, which are
     * the only thing that ends a CPU-clock sleep nothing advances): every
     * record that claims an interruption must change, which is the
     * blanket proof that these records report what the kernel did rather
     * than a constant. */
    if (ms == SIG_DELAY_MS && mutant("nosig")) return;
    memset(&it, 0, sizeof it);
    it.it_value.tv_sec  = (time_t)(ms / 1000u);
    it.it_value.tv_usec = (suseconds_t)((ms % 1000u) * 1000u);
    setitimer(ITIMER_REAL, &it, NULL);
}

void disarm_timer(void) {
    struct itimerval it;
    memset(&it, 0, sizeof it);
    setitimer(ITIMER_REAL, &it, NULL);
}

int raw_clock_nanosleep(clockid_t clk, int flags,
                        const struct timespec *req, struct timespec *rem) {
    long rv = syscall(SYS_clock_nanosleep, (long)clk, (long)flags,
                      (long)req, (long)rem);
    return (int)rv;
}

void sleep_ms(unsigned ms) {
    struct timespec req, rem;
    req.tv_sec  = (time_t)(ms / 1000u);
    req.tv_nsec = (long)((ms % 1000u) * 1000000u);
    while (raw_clock_nanosleep(CLOCK_MONOTONIC, 0, &req, &rem) < 0 && errno == EINTR)
        req = rem;
}

long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int mutant(const char *name) {
    const char *v = getenv("WAIT_DIFF_MUTANT");
    return v != NULL && strcmp(v, name) == 0;
}

pid_t spawn_writer(int fd, unsigned delay_ms, size_t len) {
    pid_t pid = fork();
    if (pid != 0) return pid;
    char buf[64];
    if (len > sizeof buf) len = sizeof buf;
    memset(buf, 'x', len);
    sleep_ms(delay_ms);
    if (write(fd, buf, len) < 0) _exit(1);
    _exit(0);
}

void wr1(int fd, char c) {
    if (write(fd, &c, 1) != 1) { /* the reader times out instead */ }
}

void reap(pid_t pid) {
    int st;
    if (pid <= 0) return;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
}
