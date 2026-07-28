/* System V shared memory: the ADDRESS-SPACE half of shmdt(2).
 *
 * `ksys_shmdt` (`ipc/shm.c`) is not "unmap a page here". It searches for a
 * VMA that is shm-backed AND whose pgoff equals its distance from
 * `shmaddr` — an attachment PLACED AT that address — then unmaps every
 * fragment of that same attachment within the segment's i_size. So the
 * whole multi-page segment goes, an interior address is EINVAL, and a
 * page-aligned address that anchors nothing is EINVAL.
 *
 * A return value cannot show any of that: a kernel that unmapped exactly
 * one page and returned 0 for any aligned address would look identical.
 * The observable is a child that writes the address and dies — hence
 * `fault_class` rather than an errno.
 */
#include "probe.h"

#include <sys/ipc.h>
#include <sys/shm.h>

#define SHM_MODE   0600
#define SHM_PAGES  3
#define SHM_MARK   'S'

static size_t g_page;

/* Write one byte at `p` in a child, so the probe survives the fault that
 * proves the address is gone. */
static const char *touch(void *p) {
    pid_t pid = fork();
    if (pid == 0) {
        *(volatile char *)p = SHM_MARK;
        _exit(0);
    }
    int st = 0;
    if (!wait_bounded(pid, SYSV_GUARD_MS, &st)) { kill(pid, SIGKILL); reap(pid); return "blocked"; }
    return fault_class(st);
}

static int shm_new(size_t bytes) { return shmget(IPC_PRIVATE, bytes, IPC_CREAT | IPC_EXCL | SHM_MODE); }
static void shm_kill(int id) { if (id >= 0) shmctl(id, IPC_RMID, NULL); }

static long nattch(int id) {
    struct shmid_ds ds;
    if (shmctl(id, IPC_STAT, &ds) < 0) return -1;
    return (long)ds.shm_nattch;
}

/* Attach, prove every page of the segment is writable, then detach and
 * prove none of it is. `sysvdt1page` swaps the shmdt for a one-page
 * munmap — the exact shape of the bug this case exists to catch — which
 * leaves page 2 mapped and shm_nattch standing. */
static void detach_case(void) {
    int id = shm_new(SHM_PAGES * g_page);
    if (id < 0) {
        out("sysv_shm", "attach_multipage", "attach=failed|page0=none|page2=none|nattch=-1");
        out("sysv_shm", "detach_whole_segment", "outcome=setup_failed|page0=none|page2=none|nattch=-1");
        out("sysv_shm", "detach_twice_einval", "outcome=setup_failed");
        return;
    }
    char *a = shmat(id, NULL, 0);
    if (a == (char *)-1) {
        out("sysv_shm", "attach_multipage", "attach=failed|page0=none|page2=none|nattch=-1");
        out("sysv_shm", "detach_whole_segment", "outcome=setup_failed|page0=none|page2=none|nattch=-1");
        out("sysv_shm", "detach_twice_einval", "outcome=setup_failed");
        shm_kill(id);
        return;
    }
    const char *p0 = touch(a);
    const char *p2 = touch(a + 2 * g_page);
    out("sysv_shm", "attach_multipage", "attach=ok|page0=%s|page2=%s|nattch=%ld", p0, p2, nattch(id));

    int rc;
    if (mutant("sysvdt1page")) rc = munmap(a, g_page);
    else rc = shmdt(a);
    int err = errno;
    const char *d0 = touch(a);
    const char *d2 = touch(a + 2 * g_page);
    out("sysv_shm", "detach_whole_segment", "outcome=%s|page0=%s|page2=%s|nattch=%ld",
        sysv_class_name(sysv_class(rc, err)), d0, d2, nattch(id));

    rc = shmdt(a);
    out("sysv_shm", "detach_twice_einval", "outcome=%s", sysv_class_name(sysv_class(rc, errno)));
    shm_kill(id);
}

/* An address that does not ANCHOR an attachment is EINVAL and unmaps
 * nothing, whether it is inside the attachment, misaligned, or a mapping
 * of some other kind. Each gets its own segment so `sysvdtbase` — which
 * hands every one of them the real attach base — changes all three
 * records without any of them disturbing the next. */
static void reject_case(const char *test, int offset, int foreign) {
    int id = shm_new(SHM_PAGES * g_page);
    if (id < 0) { out("sysv_shm", test, "outcome=setup_failed|survives=none|nattch=-1"); return; }
    char *a = shmat(id, NULL, 0);
    if (a == (char *)-1) { out("sysv_shm", test, "outcome=setup_failed|survives=none|nattch=-1"); shm_kill(id); return; }
    char *alien = NULL;
    if (foreign) {
        alien = mmap(NULL, g_page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (alien == MAP_FAILED) {
            out("sysv_shm", test, "outcome=setup_failed|survives=none|nattch=-1");
            shmdt(a); shm_kill(id); return;
        }
    }
    char *target = mutant("sysvdtbase") ? a : (foreign ? alien : a + offset);
    int rc = shmdt(target);
    int err = errno;
    /* Evaluated in order: `touch` forks, and C leaves argument order
     * unspecified, so the attach count must be sampled explicitly. */
    const char *survives = touch(foreign ? alien : a);
    long left = nattch(id);
    out("sysv_shm", test, "outcome=%s|survives=%s|nattch=%ld",
        sysv_class_name(sysv_class(rc, err)), survives, left);
    if (alien) munmap(alien, g_page);
    shmdt(a);
    shm_kill(id);
}

/* fork copies the attachment, and Linux's shm_open bumps shm_nattch for
 * the copy (`ipc/shm.c` shm_vm_ops). `sysvnofork` skips the child. */
static void fork_case(void) {
    int id = shm_new(SHM_PAGES * g_page);
    if (id < 0) { out("sysv_shm", "nattch_tracks_fork", "forked=-1|after_exit=-1"); return; }
    char *a = shmat(id, NULL, 0);
    if (a == (char *)-1) { out("sysv_shm", "nattch_tracks_fork", "forked=-1|after_exit=-1"); shm_kill(id); return; }
    int fds[2];
    if (pipe(fds) < 0) { out("sysv_shm", "nattch_tracks_fork", "forked=-1|after_exit=-1"); shmdt(a); shm_kill(id); return; }
    pid_t pid = -1;
    if (!mutant("sysvnofork")) {
        pid = fork();
        if (pid == 0) {
            char c;
            close(fds[1]);
            while (read(fds[0], &c, 1) < 0 && errno == EINTR) { }
            _exit(0);
        }
    }
    close(fds[0]);
    sleep_ms(SYSV_SETTLE_MS);
    long forked = nattch(id);
    close(fds[1]);
    if (pid > 0) reap(pid);
    out("sysv_shm", "nattch_tracks_fork", "forked=%ld|after_exit=%ld", forked, nattch(id));
    shmdt(a);
    shm_kill(id);
}

void probe_sysv_shm(void) {
    long ps = sysconf(_SC_PAGESIZE);
    int probe;
    if (ps <= 0) { out("sysv_shm", "setup", "shm=no_pagesize"); return; }
    g_page = (size_t)ps;
    probe = shm_new(g_page);
    if (probe < 0) { out("sysv_shm", "setup", "shm=unavailable|errno=%s", errno_name(errno)); return; }
    shm_kill(probe);
    out("sysv_shm", "setup", "shm=ok|pages=%d", SHM_PAGES);
    detach_case();
    reject_case("detach_interior_einval", (int)g_page, 0);
    reject_case("detach_unaligned_einval", 1, 0);
    reject_case("detach_foreign_mapping_einval", 0, 1);
    fork_case();
}
