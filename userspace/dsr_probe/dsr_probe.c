// /bin/dsr_probe — DSR/CPR answerback regression for /dev/console.
//
// Proves the system console (/dev/console, vt 0) answers a Device-Status-
// Report cursor query LOCALLY, the Linux fb-console way: the kernel VT
// emulator (vc_cons[0]) parses `ESC[6n`, queues a CPR reply, and the tick
// drain injects it back into this tty's input ring. Before the /dev/console
// → vc_data unify the query went out the serial wire and no oxide reply ever
// came back (the read below would hang) — the SIGALRM timeout converts that
// failure into a printed FAIL instead of a wedged boot.
//
// Move the cursor to the far corner first (`ESC[999;999H`, clamped to the
// real grid) so the CPR reports the console GEOMETRY — the same probe btop
// uses to size itself to the console.

#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <termios.h>

static volatile sig_atomic_t timed_out = 0;
static void on_alrm(int s) { (void)s; timed_out = 1; }

static void emit(const char *m) { write(1, m, strlen(m)); }

// Append a decimal u32 to buf at *pos.
static void putdec(char *buf, int *pos, unsigned v) {
    char tmp[12]; int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    while (n) buf[(*pos)++] = tmp[--n];
}

int main(void) {
    struct termios orig, raw;
    int have_tio = (tcgetattr(0, &orig) == 0);
    if (have_tio) {
        raw = orig;
        // Raw input: no canonical line-buffering, no echo — the CPR reply
        // (which ends in 'R', not '\n') must come back byte-for-byte and
        // must not be echoed to the screen.
        raw.c_lflag &= ~(unsigned)(ICANON | ECHO | ISIG | IEXTEN);
        raw.c_iflag &= ~(unsigned)(ICRNL | INLCR | ISTRIP);
        raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
        tcsetattr(0, TCSANOW, &raw);
    }

    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alrm;            // no SA_RESTART → read() returns EINTR
    sigaction(SIGALRM, &sa, 0);
    alarm(3);

    // Park the cursor at the bottom-right corner (clamped to the grid) so the
    // CPR reports the console geometry, then issue the DSR cursor query.
    write(1, "\033[999;999H\033[6n", 13);

    char buf[64]; int len = 0;
    while (len < (int)sizeof buf - 1 && !timed_out) {
        char c;
        long n = read(0, &c, 1);
        if (n <= 0) break;             // EINTR (alarm) or EOF
        buf[len++] = c;
        if (c == 'R') break;
    }
    buf[len] = '\0';
    alarm(0);
    if (have_tio) tcsetattr(0, TCSANOW, &orig);

    // Parse ESC [ <rows> ; <cols> R.
    unsigned rows = 0, cols = 0;
    int ok = 0;
    if (len >= 6 && buf[0] == '\033' && buf[1] == '[') {
        int i = 2; while (i < len && buf[i] >= '0' && buf[i] <= '9') rows = rows * 10 + (buf[i++] - '0');
        if (i < len && buf[i] == ';') {
            i++;
            while (i < len && buf[i] >= '0' && buf[i] <= '9') cols = cols * 10 + (buf[i++] - '0');
            if (i < len && buf[i] == 'R' && rows > 0 && cols > 0) ok = 1;
        }
    }

    char out[64]; int p = 0;
    const char *tag = ok ? "dsr_probe: PASS rows=" : "dsr_probe: FAIL rows=";
    memcpy(out + p, tag, strlen(tag)); p += (int)strlen(tag);
    putdec(out, &p, rows); out[p++] = ' ';
    out[p++] = 'c'; out[p++] = 'o'; out[p++] = 'l'; out[p++] = 's'; out[p++] = '=';
    putdec(out, &p, cols); out[p++] = '\n';
    write(1, out, p);
    (void)emit;
    return ok ? 0 : 1;
}
