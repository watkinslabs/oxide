/* openat2(2) RESOLVE_* scoping — does the sandbox hold on the CREATE path?
 *
 * `fs/open.c` build_open_flags folds every RESOLVE_* bit into ONE
 * `op->lookup_flags`, and `fs/namei.c` path_openat runs the LOOKUP_PARENT
 * walk that O_CREAT needs with the SAME `nd->flags`. There is no create-path
 * exception, so a scoping bit that stops constraining resolution the moment a
 * create is involved is a sandbox escape.
 *
 * Every case is rooted in a private mkdtemp() and reports only the OUTCOME
 * (named errno + whether the escape target exists), never a path, so the host
 * oracle and the guest print identical records regardless of uid or /tmp
 * contents.
 *
 * Layout built per case:
 *   <base>/box          the dirfd — the scope
 *   <base>/box/sub      an ordinary child, inside the scope
 *   <base>/outside      the escape target, one level ABOVE the scope
 */
#include "probe.h"

#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV       0x01
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS 0x02
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS   0x04
#endif
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH       0x08
#endif
#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT       0x10
#endif

/* glibc has no openat2 wrapper on either arch; the raw slot is the ABI under
 * test anyway (the wrapper would only re-pack the same struct). */
/* mkdtemp template is 17 bytes; a small fixed base keeps every derived
 * snprintf provably short of PATH_MAX (the probe builds with -Werror). */
#define O2_BASE_MAX 32

struct o2_how { uint64_t flags; uint64_t mode; uint64_t resolve; };

static int o2(int dfd, const char *path, uint64_t flags, uint64_t mode, uint64_t resolve) {
    struct o2_how how;
    memset(&how, 0, sizeof how);
    how.flags = flags;
    how.mode = mode;
    how.resolve = resolve;
    return (int)syscall(SYS_openat2, dfd, path, &how, sizeof how);
}

/* Build <base>/{box,box/sub,outside} and return an O_PATH-free dirfd on box.
 * `base` must be PATH_MAX-sized; it receives the mkdtemp() result. */
static int make_scope(char *base, size_t baselen) {
    char p[O2_BASE_MAX + 32];
    snprintf(base, baselen, "/tmp/o2res.XXXXXX");
    if (!mkdtemp(base)) return -1;
    snprintf(p, sizeof p, "%s/box", base);     if (mkdir(p, 0700) < 0) return -1;
    snprintf(p, sizeof p, "%s/box/sub", base); if (mkdir(p, 0700) < 0) return -1;
    snprintf(p, sizeof p, "%s/outside", base); if (mkdir(p, 0700) < 0) return -1;
    snprintf(p, sizeof p, "%s/box", base);
    return open(p, O_RDONLY | O_DIRECTORY);
}

static int exists(const char *base, const char *rel) {
    char p[O2_BASE_MAX + 32];
    struct stat st;
    snprintf(p, sizeof p, "%s/%s", base, rel);
    return stat(p, &st) == 0 ? 1 : 0;
}

static void cleanup(const char *base) {
    char p[O2_BASE_MAX + 32];
    snprintf(p, sizeof p, "%s/outside/esc", base);  unlink(p);
    snprintf(p, sizeof p, "%s/box/esc", base);      unlink(p);
    snprintf(p, sizeof p, "%s/box/sub/esc", base);  unlink(p);
    snprintf(p, sizeof p, "%s/box/link", base);     unlink(p);
    snprintf(p, sizeof p, "%s/box/dangle", base);   unlink(p);
    snprintf(p, sizeof p, "%s/box/sub", base);      rmdir(p);
    snprintf(p, sizeof p, "%s/box", base);          rmdir(p);
    snprintf(p, sizeof p, "%s/outside", base);      rmdir(p);
    rmdir(base);
}

/* One create attempt: report the named errno and whether the file landed
 * OUTSIDE the scope. `escaped=1` on either kernel is the defect. */
static void create_case(const char *test, const char *path, uint64_t resolve) {
    char base[O2_BASE_MAX];
    int dfd = make_scope(base, sizeof base);
    int fd, err, esc;
    if (dfd < 0) { out("openat2", test, "setup=FAIL"); return; }
    errno = 0;
    fd = o2(dfd, path, O_WRONLY | O_CREAT, 0600, resolve);
    err = errno;
    if (fd >= 0) close(fd);
    esc = exists(base, "outside/esc");
    out("openat2", test, "ret=%s|errno=%s|escaped=%d|in_scope=%d",
        fd >= 0 ? "ok" : "err", fd >= 0 ? "OK" : errno_name(err), esc,
        exists(base, "box/esc") || exists(base, "box/sub/esc"));
    close(dfd);
    cleanup(base);
}

/* Same, but the path traverses a symlink planted at <base>/box/link that
 * points OUT of the scope. */
static void create_case_via_symlink(const char *test, const char *path, uint64_t resolve) {
    char base[O2_BASE_MAX], p[PATH_MAX];
    int dfd = make_scope(base, sizeof base);
    int fd, err;
    if (dfd < 0) { out("openat2", test, "setup=FAIL"); return; }
    snprintf(p, sizeof p, "%s/box/link", base);
    if (symlink("../outside", p) < 0) { out("openat2", test, "setup=FAIL"); close(dfd); cleanup(base); return; }
    errno = 0;
    fd = o2(dfd, path, O_WRONLY | O_CREAT, 0600, resolve);
    err = errno;
    if (fd >= 0) close(fd);
    out("openat2", test, "ret=%s|errno=%s|escaped=%d",
        fd >= 0 ? "ok" : "err", fd >= 0 ? "OK" : errno_name(err),
        exists(base, "outside/esc"));
    close(dfd);
    cleanup(base);
}

void probe_openat2_resolve(void) {
    /* openat2 itself must exist before any scoping claim means anything. */
    {
        char base[O2_BASE_MAX];
        int dfd = make_scope(base, sizeof base);
        int fd = dfd < 0 ? -1 : o2(dfd, "sub", O_RDONLY, 0, 0);
        int err = errno;
        out("openat2", "supported", "ret=%s|errno=%s",
            fd >= 0 ? "ok" : "err", fd >= 0 ? "OK" : errno_name(err));
        if (fd >= 0) close(fd);
        if (dfd >= 0) { close(dfd); cleanup(base); }
    }

    /* Control: an ordinary in-scope create must still work under each
     * scoping bit, so a "refuses everything" kernel cannot read as a pass. */
    create_case("in_root_create_inside",  "sub/esc", RESOLVE_IN_ROOT);
    create_case("beneath_create_inside",  "sub/esc", RESOLVE_BENEATH);
    create_case("nosym_create_inside",    "sub/esc", RESOLVE_NO_SYMLINKS);

    /* THE ESCAPE. RESOLVE_IN_ROOT *clamps* `..` at the dirfd rather than
     * erroring, so the scoped walk of `../outside/esc` ends at
     * box/outside/esc → ENOENT. A kernel that then re-resolves the PARENT
     * unscoped lands on <base>/outside and creates there: escaped=1. */
    create_case("in_root_create_dotdot", "../outside/esc", RESOLVE_IN_ROOT);

    /* Same escape reached by an ABSOLUTE pathname: under IN_ROOT the dirfd is
     * "/", so any absolute path must restart INSIDE the box. Unscoped parent
     * resolution instead honours the real root. `/tmp` exists on both kernels;
     * the box has no `tmp` child, so the correct answer is ENOENT. */
    create_case("in_root_create_absolute", "/tmp/o2res-nonexistent/esc", RESOLVE_IN_ROOT);

    /* RESOLVE_BENEATH errors instead of clamping: `..` at the scoped root is
     * EXDEV, and an absolute pathname is EXDEV, create or not. */
    create_case("beneath_create_dotdot",   "../outside/esc", RESOLVE_BENEATH);
    create_case("beneath_create_absolute", "/tmp/o2res-nonexistent/esc", RESOLVE_BENEATH);

    /* RESOLVE_NO_SYMLINKS: ANY symlink anywhere in the walk is ELOOP — the
     * parent walk of a create included. */
    create_case_via_symlink("nosym_create_via_symlink", "link/esc", RESOLVE_NO_SYMLINKS);
    /* ...and with no scoping bit the same path is the baseline that proves the
     * symlink really does lead out of the box (escaped=1 is CORRECT here). */
    create_case_via_symlink("unscoped_create_via_symlink", "link/esc", 0);

    /* RESOLVE_BENEATH must also refuse the symlink escape (its target is
     * relative and walks `..` above the scoped root → EXDEV). */
    create_case_via_symlink("beneath_create_via_symlink", "link/esc", RESOLVE_BENEATH);

    /* Unknown resolve bits and the mutually-exclusive scoping pair are EINVAL
     * (`build_open_flags`), checked before any walk happens. */
    {
        char base[O2_BASE_MAX];
        int dfd = make_scope(base, sizeof base);
        int fd, err;
        if (dfd < 0) { out("openat2", "resolve_validation", "setup=FAIL"); return; }
        errno = 0; fd = o2(dfd, "sub", O_RDONLY, 0, 0x40);
        err = errno;
        out("openat2", "unknown_resolve_bit", "ret=%s|errno=%s",
            fd >= 0 ? "ok" : "err", fd >= 0 ? "OK" : errno_name(err));
        if (fd >= 0) close(fd);
        errno = 0; fd = o2(dfd, "sub", O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT);
        err = errno;
        out("openat2", "beneath_plus_in_root", "ret=%s|errno=%s",
            fd >= 0 ? "ok" : "err", fd >= 0 ? "OK" : errno_name(err));
        if (fd >= 0) close(fd);
        close(dfd);
        cleanup(base);
    }
}
