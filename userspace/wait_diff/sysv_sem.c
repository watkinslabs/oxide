/* System V semaphores: the SLEEPING half of semop(2)/semtimedop(2) plus
 * SEM_UNDO, neither of which any booted program on this image calls.
 *
 * `semop` is NOT restarted by SA_RESTART. `ipc/sem.c:2158` seeds
 * `queue.status` with `-EINTR` and the wake loop
 * (`while (error == -EINTR && !signal_pending(current))`, `ipc/sem.c:2211`)
 * leaves with that value the moment a signal is pending — there is no
 * `-ERESTARTSYS` anywhere in the file, so the errno reaches userspace
 * whatever `sa_flags` says. The two `signal_*` cases below are therefore
 * deliberately identical, and that identity IS the assertion; a kernel
 * that routed semop through the restart machinery would show `ok` on the
 * SA_RESTART arm.
 *
 * Every case that must park has a peer which acts only after
 * SYSV_SETTLE_MS, and no case mixes a signal with a release, so nothing
 * here races the way B1449 raced.
 */
#include "probe.h"

#include <sys/ipc.h>
#include <sys/sem.h>

/* glibc deliberately does not declare `union semun` (it is the caller's
 * per-arch business, X/Open says so). */
union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

#define SEM_MODE 0600
#define SEM_N    1

static int sem_new(int val) {
    int id = semget(IPC_PRIVATE, SEM_N, IPC_CREAT | IPC_EXCL | SEM_MODE);
    if (id < 0) return -1;
    union semun a;
    a.val = val;
    if (semctl(id, 0, SETVAL, a) < 0) { semctl(id, 0, IPC_RMID); return -1; }
    return id;
}

static void sem_kill(int id) { if (id >= 0) semctl(id, 0, IPC_RMID); }

static int sem_val(int id) { return semctl(id, 0, GETVAL); }

static int sem_apply(int id, short op, short flg) {
    struct sembuf sb;
    sb.sem_num = 0;
    sb.sem_op = op;
    sb.sem_flg = flg;
    return semop(id, &sb, 1);
}

/* Run one blocking semop in a child and hand the classification back in
 * the exit code. `sig` < 0 installs no handler; otherwise it is the
 * SA_RESTART argument and an itimer fires inside the wait. */
static void sem_blocker(int id, short op, short flg, int sig, unsigned slept_ms) {
    long long t0;
    int rc, err;
    /* fork inherits the counter, and earlier probes have already raised
     * it; a case that installs no handler must still report sig=0. */
    g_sig_count = 0;
    if (sig >= 0) { install_handler(SIGALRM, sig); arm_timer_ms(SIG_DELAY_MS); }
    t0 = mono_ms();
    rc = sem_apply(id, op, flg);
    err = errno;
    disarm_timer();
    int code = sysv_class(rc, err);
    if (mono_ms() - t0 >= (long long)slept_ms) code |= SV_SLEPT;
    if (g_sig_count) code |= SV_SIG;
    _exit(code);
}

static void report_child(const char *test, pid_t pid, unsigned guard_ms) {
    int st = 0;
    if (!wait_bounded(pid, guard_ms, &st)) {
        kill(pid, SIGKILL);
        reap(pid);
        out("sysv_sem", test, "outcome=blocked|slept=0|sig=0");
        return;
    }
    if (!WIFEXITED(st)) { out("sysv_sem", test, "outcome=killed|slept=0|sig=0"); return; }
    int code = WEXITSTATUS(st);
    out("sysv_sem", test, "outcome=%s|slept=%d|sig=%d",
        sysv_class_name(code & SV_CLS_MASK),
        (code & SV_SLEPT) ? 1 : 0, (code & SV_SIG) ? 1 : 0);
}

/* IPC_NOWAIT on an op that cannot proceed: EAGAIN, never a park.
 * `sysvavail` posts the semaphore first, so the same code path returns
 * `ok` — the record cannot be a constant. */
static void nowait_case(void) {
    int id = sem_new(mutant("sysvavail") ? 1 : 0);
    if (id < 0) { out("sysv_sem", "nowait_eagain", "outcome=setup_failed|slept=0|sig=0"); return; }
    int rc = sem_apply(id, -1, IPC_NOWAIT);
    int err = errno;
    out("sysv_sem", "nowait_eagain", "outcome=%s|slept=0|sig=0", sysv_class_name(sysv_class(rc, err)));
    sem_kill(id);
}

/* The decrement parks until a peer posts. `slept` is the second
 * observable a degenerate "never blocks, returns 0" implementation cannot
 * fake (the B1450 lesson). */
static void block_until_posted(void) {
    int id = sem_new(0);
    if (id < 0) { out("sysv_sem", "block_until_posted", "outcome=setup_failed|slept=0|sig=0"); return; }
    pid_t pid = fork();
    if (pid == 0) sem_blocker(id, -1, 0, -1, SYSV_SLEPT_MS);
    sleep_ms(SYSV_RELEASE_MS);
    if (!mutant("sysvnopost")) sem_apply(id, 1, 0);
    report_child("block_until_posted", pid, SYSV_GUARD_MS);
    sem_kill(id);
}

/* sem_op == 0 is wait-for-zero, a distinct blocking rule from the
 * decrement: it parks while semval is NON-zero and needs only read
 * permission. */
static void wait_for_zero(void) {
    int id = sem_new(2);
    if (id < 0) { out("sysv_sem", "wait_for_zero", "outcome=setup_failed|slept=0|sig=0"); return; }
    pid_t pid = fork();
    if (pid == 0) sem_blocker(id, 0, 0, -1, SYSV_SLEPT_MS);
    sleep_ms(SYSV_RELEASE_MS);
    if (!mutant("sysvnopost")) sem_apply(id, -2, 0);
    report_child("wait_for_zero", pid, SYSV_GUARD_MS);
    sem_kill(id);
}

/* semncnt/semzcnt against REAL parked waiters. Both waiters drain off one
 * post: semval 1 -> 2 lets the -2 through (-> 0), and 0 is what the
 * wait-for-zero waiter needs, so the record also proves the commit of one
 * waiter wakes the next. */
static void counted_waiters(void) {
    int id = sem_new(1);
    if (id < 0) { out("sysv_sem", "waiter_counts", "ncnt=-1|zcnt=-1|dec=setup_failed|zero=setup_failed"); return; }
    pid_t dec = fork();
    if (dec == 0) sem_blocker(id, -2, 0, -1, SYSV_SLEPT_MS);
    pid_t zero = fork();
    if (zero == 0) sem_blocker(id, 0, 0, -1, SYSV_SLEPT_MS);
    sleep_ms(SYSV_SETTLE_MS);
    int ncnt = semctl(id, 0, GETNCNT);
    int zcnt = semctl(id, 0, GETZCNT);
    sem_apply(id, 1, 0);
    int sd = 0, sz = 0;
    int ok_d = wait_bounded(dec, SYSV_GUARD_MS, &sd);
    int ok_z = wait_bounded(zero, SYSV_GUARD_MS, &sz);
    if (!ok_d) { kill(dec, SIGKILL); reap(dec); }
    if (!ok_z) { kill(zero, SIGKILL); reap(zero); }
    out("sysv_sem", "waiter_counts", "ncnt=%d|zcnt=%d|dec=%s|zero=%s", ncnt, zcnt,
        ok_d && WIFEXITED(sd) ? sysv_class_name(WEXITSTATUS(sd) & SV_CLS_MASK) : "blocked",
        ok_z && WIFEXITED(sz) ? sysv_class_name(WEXITSTATUS(sz) & SV_CLS_MASK) : "blocked");
    sem_kill(id);
}

/* Nobody ever posts, so the itimer is the only way out and `eintr` cannot
 * be a message that arrived first. `nosig` removes the itimer, which
 * turns both records into `blocked`. */
static void signal_case(const char *test, int restart) {
    int id = sem_new(0);
    if (id < 0) { out("sysv_sem", test, "outcome=setup_failed|slept=0|sig=0"); return; }
    pid_t pid = fork();
    if (pid == 0) sem_blocker(id, -1, 0, restart, SYSV_SLEPT_MS);
    report_child(test, pid, SYSV_GUARD_MS);
    sem_kill(id);
}

/* semtimedop's relative timeout expires with EAGAIN, and `slept` proves
 * the kernel actually waited it out instead of polling once. */
static void timeout_case(void) {
    int id = sem_new(0);
    if (id < 0) { out("sysv_sem", "timedop_eagain", "outcome=setup_failed|slept=0|sig=0"); return; }
    pid_t pid = fork();
    if (pid == 0) {
        struct sembuf sb;
        struct timespec ts;
        sb.sem_num = 0; sb.sem_op = -1; sb.sem_flg = 0;
        ts.tv_sec = SYSV_TIMEOUT_MS / 1000u;
        ts.tv_nsec = (long)((SYSV_TIMEOUT_MS % 1000u) * 1000000u);
        long long t0 = mono_ms();
        int rc = semtimedop(id, &sb, 1, &ts);
        int err = errno;
        int code = sysv_class(rc, err);
        if (mono_ms() - t0 >= (long long)SYSV_TIMED_MS) code |= SV_SLEPT;
        _exit(code);
    }
    report_child("timedop_eagain", pid, SYSV_GUARD_MS);
    sem_kill(id);
}

/* IPC_RMID landing on a parked waiter is EIDRM, not a lost wakeup.
 * `sysvnormid` skips the removal, so the waiter stays parked. */
static void rmid_case(void) {
    int id = sem_new(0);
    if (id < 0) { out("sysv_sem", "rmid_eidrm", "outcome=setup_failed|slept=0|sig=0"); return; }
    pid_t pid = fork();
    if (pid == 0) sem_blocker(id, -1, 0, -1, SYSV_SLEPT_MS);
    sleep_ms(SYSV_SETTLE_MS);
    if (!mutant("sysvnormid")) sem_kill(id);
    report_child("rmid_eidrm", pid, SYSV_GUARD_MS);
    sem_kill(id);
}

/* SEM_UNDO is applied by exit_sem, not by the operation: the adjustment
 * must be visible as an unmodified semval for as long as the process
 * lives, and reverted the moment it does not. `sysvnoundo` drops the flag,
 * which leaves the post standing. */
static void undo_case(const char *test, int flg) {
    int id = sem_new(0);
    if (id < 0) { out("sysv_sem", test, "live=-1|after_exit=-1"); return; }
    int fds[2];
    if (pipe(fds) < 0) { out("sysv_sem", test, "live=-1|after_exit=-1"); sem_kill(id); return; }
    pid_t pid = fork();
    if (pid == 0) {
        char c;
        close(fds[1]);
        if (sem_apply(id, 1, (short)flg) < 0) _exit(1);
        /* Parks until the parent has read semval and closed its end. */
        while (read(fds[0], &c, 1) < 0 && errno == EINTR) { }
        _exit(0);
    }
    close(fds[0]);
    sleep_ms(SYSV_SETTLE_MS);
    int live = sem_val(id);
    close(fds[1]);
    reap(pid);
    out("sysv_sem", test, "live=%d|after_exit=%d", live, sem_val(id));
    sem_kill(id);
}

void probe_sysv_sem(void) {
    int probe = semget(IPC_PRIVATE, SEM_N, IPC_CREAT | IPC_EXCL | SEM_MODE);
    if (probe < 0) {
        out("sysv_sem", "setup", "sem=unavailable|errno=%s", errno_name(errno));
        return;
    }
    semctl(probe, 0, IPC_RMID);
    out("sysv_sem", "setup", "sem=ok");
    nowait_case();
    block_until_posted();
    wait_for_zero();
    counted_waiters();
    signal_case("signal_sarestart", 1);
    signal_case("signal_norestart", 0);
    timeout_case();
    rmid_case();
    undo_case("undo_reverted_on_exit", mutant("sysvnoundo") ? 0 : SEM_UNDO);
    undo_case("no_undo_survives_exit", 0);
}
