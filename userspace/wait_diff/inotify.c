/* inotify(7) EVENT LAYOUT — the exact bytes a directory watcher reads.
 *
 * `struct inotify_event` is variable-length: a 16-byte header followed by a
 * NUL-padded name whose `len` is `roundup(strlen(name) + 1, 16)` — rounded to
 * sizeof(struct inotify_event), NOT to 4 (fs/notify/inotify/inotify_user.c
 * `round_event_name_len`). Everything a desktop reacts to is downstream of
 * that name: systemd `.path` units, udev, `GFileMonitor`, Nautilus, dconf.
 * Before B1463 oxide hardwired `len = 0` and threw the name away, so every
 * watcher learned THAT something changed and never WHICH file.
 *
 * The host kernel is the oracle for these bytes, which is why the cases print
 * the padded `len` and the recovered name verbatim rather than a bucket: there
 * is no legitimate room for the two kernels to disagree.
 *
 * `short_buf` is the one case about a return value: a reader whose buffer
 * cannot hold the NEXT WHOLE event gets EINVAL, never a truncated event
 * (`get_one_event` returns `ERR_PTR(-EINVAL)`).
 */
#include "probe.h"
#include <sys/inotify.h>

#define EV_HDR   ((int)sizeof(struct inotify_event))
#define EVBUF    4096
#define WAIT_MS  2000

/* One decoded event, flattened so a record never prints a pointer. */
struct ev { uint32_t mask, cookie, len; char name[256]; };

static char g_dir[64];

/* Symbolic mask so a record never depends on a numeric constant matching. */
static void mask_name(uint32_t m, char *out_buf, size_t n) {
    const struct { uint32_t bit; const char *name; } tab[] = {
        { IN_CREATE, "CREATE" }, { IN_DELETE, "DELETE" }, { IN_MODIFY, "MODIFY" },
        { IN_MOVED_FROM, "MOVED_FROM" }, { IN_MOVED_TO, "MOVED_TO" },
        { IN_ATTRIB, "ATTRIB" }, { IN_OPEN, "OPEN" }, { IN_ACCESS, "ACCESS" },
        { IN_CLOSE_WRITE, "CLOSE_WRITE" }, { IN_CLOSE_NOWRITE, "CLOSE_NOWRITE" },
        { IN_DELETE_SELF, "DELETE_SELF" }, { IN_MOVE_SELF, "MOVE_SELF" },
        { IN_IGNORED, "IGNORED" }, { IN_Q_OVERFLOW, "Q_OVERFLOW" },
        { IN_ISDIR, "ISDIR" },
    };
    out_buf[0] = '\0';
    size_t used = 0;
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++) {
        if (!(m & tab[i].bit)) continue;
        int w = snprintf(out_buf + used, n - used, "%s%s", used ? "," : "", tab[i].name);
        if (w < 0 || (size_t)w >= n - used) break;
        used += (size_t)w;
        m &= ~tab[i].bit;
    }
    if (m && used < n) snprintf(out_buf + used, n - used, "%s?", used ? "," : "");
    if (!out_buf[0]) snprintf(out_buf, n, "none");
}

static int ready(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    return poll(&p, 1, WAIT_MS) == 1 && (p.revents & POLLIN);
}

/* Drain up to `max` events. Returns the count, or -1 with errno set. */
static int drain(int fd, struct ev *evs, int max) {
    char buf[EVBUF];
    if (!ready(fd)) { errno = ETIMEDOUT; return -1; }
    ssize_t n = read(fd, buf, sizeof buf);
    if (n < 0) return -1;
    int got = 0;
    for (ssize_t o = 0; o + EV_HDR <= n && got < max; ) {
        struct inotify_event e;
        memcpy(&e, buf + o, sizeof e);
        evs[got].mask = e.mask;
        evs[got].cookie = e.cookie;
        evs[got].len = e.len;
        evs[got].name[0] = '\0';
        if (e.len) {
            size_t cap = e.len < sizeof evs[got].name ? e.len : sizeof evs[got].name - 1;
            memcpy(evs[got].name, buf + o + EV_HDR, cap);
            evs[got].name[cap] = '\0';
        }
        if (mutant("inoname")) evs[got].name[0] = '\0';
        if (mutant("inolen")) evs[got].len = (uint32_t)strlen(evs[got].name);
        got++;
        o += EV_HDR + (ssize_t)e.len;
    }
    return got;
}

/* `g_dir` is a fixed-shape mkdtemp result and every leaf is a literal, so the
 * concatenation cannot truncate; the cast silences the compiler's worst case. */
static void path_in(char *dst, size_t n, const char *leaf) {
    int w = snprintf(dst, n, "%s/%s", g_dir, leaf);
    if (w < 0 || (size_t)w >= n) dst[0] = '\0';
}

static int make_file(const char *leaf) {
    char p[128];
    path_in(p, sizeof p, leaf);
    int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
    return fd;
}

/* Create `leaf` under a fresh IN_CREATE watch and report the ONE event. */
static void create_case(const char *test, const char *leaf, int as_dir) {
    int fd = inotify_init1(0);
    if (fd < 0) { out("inotify", test, "init=%s", errno_name(errno)); return; }
    int wd = inotify_add_watch(fd, g_dir, IN_CREATE);
    if (wd < 0) { out("inotify", test, "watch=%s", errno_name(errno)); close(fd); return; }

    char p[128];
    path_in(p, sizeof p, leaf);
    if (as_dir) {
        if (mkdir(p, 0700) < 0) { out("inotify", test, "mk=%s", errno_name(errno)); close(fd); return; }
    } else {
        int f = make_file(leaf);
        if (f < 0) { out("inotify", test, "mk=%s", errno_name(errno)); close(fd); return; }
        close(f);
    }

    struct ev evs[4];
    int n = drain(fd, evs, 4);
    if (n < 1) { out("inotify", test, "outcome=noevent|errno=%s", errno_name(errno)); close(fd); return; }
    char m[128];
    mask_name(evs[0].mask, m, sizeof m);
    out("inotify", test, "n=%d|wd_ok=%d|mask=%s|len=%u|name=%s",
        n, evs[0].mask ? wd > 0 : 0, m, evs[0].len, evs[0].name);
    if (as_dir) rmdir(p); else unlink(p);
    close(fd);
}

/* A rename inside the watched directory: BOTH halves must name their own
 * entry, and one cookie must pair them. */
static void move_case(void) {
    int fd = inotify_init1(0);
    if (fd < 0) { out("inotify", "move_names", "init=%s", errno_name(errno)); return; }
    if (inotify_add_watch(fd, g_dir, IN_MOVED_FROM | IN_MOVED_TO) < 0) {
        out("inotify", "move_names", "watch=%s", errno_name(errno)); close(fd); return;
    }
    int f = make_file("mv-src");
    if (f < 0) { out("inotify", "move_names", "mk=%s", errno_name(errno)); close(fd); return; }
    close(f);
    char from[128], to[128];
    path_in(from, sizeof from, "mv-src");
    path_in(to, sizeof to, "mv-dst");
    if (rename(from, to) < 0) { out("inotify", "move_names", "rename=%s", errno_name(errno)); close(fd); return; }

    struct ev evs[4];
    int n = drain(fd, evs, 4);
    if (n < 2) { out("inotify", "move_names", "outcome=short|n=%d|errno=%s", n, errno_name(errno)); close(fd); return; }
    char m0[128], m1[128];
    mask_name(evs[0].mask, m0, sizeof m0);
    mask_name(evs[1].mask, m1, sizeof m1);
    out("inotify", "move_names", "n=%d|from=%s|from_name=%s|to=%s|to_name=%s|paired=%d|cookie_set=%d",
        n, m0, evs[0].name, m1, evs[1].name,
        evs[0].cookie == evs[1].cookie, evs[0].cookie != 0);
    unlink(to);
    close(fd);
}

/* Linux `fsnotify_parent`: a write to a file INSIDE a watched directory is
 * reported on the directory's mark, naming the file. A directory watch that
 * only ever sees events on the directory node itself is useless to every
 * file-monitor library there is. */
static void child_modify_case(void) {
    int f = make_file("child-w");
    if (f < 0) { out("inotify", "child_modify", "mk=%s", errno_name(errno)); return; }
    int fd = inotify_init1(0);
    if (fd < 0) { out("inotify", "child_modify", "init=%s", errno_name(errno)); close(f); return; }
    if (inotify_add_watch(fd, g_dir, IN_MODIFY) < 0) {
        out("inotify", "child_modify", "watch=%s", errno_name(errno)); close(fd); close(f); return;
    }
    if (!mutant("inochild") && write(f, "x", 1) != 1) {
        out("inotify", "child_modify", "write=%s", errno_name(errno)); close(fd); close(f); return;
    }
    struct ev evs[4];
    int n = drain(fd, evs, 4);
    if (n < 1) { out("inotify", "child_modify", "outcome=noevent|errno=%s", errno_name(errno)); goto done; }
    char m[128];
    mask_name(evs[0].mask, m, sizeof m);
    out("inotify", "child_modify", "n=%d|mask=%s|len=%u|name=%s", n, m, evs[0].len, evs[0].name);
done:
    close(fd);
    close(f);
    char p[128];
    path_in(p, sizeof p, "child-w");
    unlink(p);
}

/* A buffer that cannot hold the next whole event is EINVAL, and the event
 * survives for the next adequately sized read. */
static void short_buf_case(void) {
    int fd = inotify_init1(0);
    if (fd < 0) { out("inotify", "short_buf", "init=%s", errno_name(errno)); return; }
    if (inotify_add_watch(fd, g_dir, IN_CREATE) < 0) {
        out("inotify", "short_buf", "watch=%s", errno_name(errno)); close(fd); return;
    }
    int f = make_file("sb");           /* "sb" + NUL -> 16 bytes padded -> 32 total */
    if (f < 0) { out("inotify", "short_buf", "mk=%s", errno_name(errno)); close(fd); return; }
    close(f);
    if (!ready(fd)) { out("inotify", "short_buf", "outcome=noevent"); close(fd); return; }

    char small[EVBUF];
    /* 31 bytes cannot hold the 32-byte "sb" record; the mutant hands read()
     * a buffer that can, so the record stops being about the short case. */
    size_t want = mutant("inobuf") ? sizeof small : (size_t)(EV_HDR * 2 - 1);
    ssize_t rc = read(fd, small, want);
    int err = errno;
    struct ev evs[2];
    int n = rc < 0 ? drain(fd, evs, 2) : 0;
    out("inotify", "short_buf", "rc=%d|errno=%s|refetch_n=%d|refetch_name=%s",
        (int)(rc < 0 ? -1 : rc), errno_name(rc < 0 ? err : 0), n,
        n > 0 ? evs[0].name : "");
    char p[128];
    path_in(p, sizeof p, "sb");
    unlink(p);
    close(fd);
}

void probe_inotify(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/wait-diff-inotify-XXXXXX");
    if (mkdtemp(g_dir) == NULL) {
        out("inotify", "setup", "mkdtemp=%s", errno_name(errno));
        return;
    }
    out("inotify", "setup", "ok=1");
    create_case("create_name", "probe-file.txt", 0);
    /* 15 chars + NUL exactly fills one 16-byte header; 16 chars spills into a
     * second. A kernel that rounded to 4 (or reported the raw length) gets
     * both of these wrong. */
    create_case("pad_fills_one", "abcdefghijklmno", 0);
    create_case("pad_spills_two", "abcdefghijklmnop", 0);
    create_case("mkdir_isdir", "probe-subdir", 1);
    move_case();
    child_modify_case();
    short_buf_case();
    rmdir(g_dir);
}
