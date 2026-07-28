#include "probe.h"

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    /* A dead peer must never take the probe down mid-record. */
    signal(SIGPIPE, SIG_IGN);
    out("meta", "format", "wait_diff=1");
    /* Order is deliberate: `probe_locks` runs LAST because oxide stalls
     * inside fcntl(F_SETLKW) in a way no in-probe guard can bound — the
     * parent never reaches its own poll timeout, so the park looks
     * unkillable from userspace (the class F745/F747 fixed for mqueue).
     * With locks first that one defect cost the 21 records behind it and
     * every other probe read as "unknown". Keep the cheap, collectible
     * evidence in front of the case that can swallow the run. */
    /* `spinsig` runs before `sigfpu` for the same reason `locks` runs last:
     * both spin in userspace, but sigfpu's only guard is its own `alarm()` —
     * the very delivery path spinsig measures — so on a kernel that cannot
     * signal a spinning task sigfpu swallows the run. Collect the three rows
     * that NAME that defect before the case it disables. */
    probe_spinsig();
    probe_sigfpu();
    probe_sleep();
    probe_inotify();
    probe_fdwait();
    probe_readiness();
    probe_jobctl();
    probe_cputime();
    probe_latency();
    probe_mqueue();
    probe_mqueue_api();
    probe_sysv_sem();
    probe_sysv_msg();
    probe_sysv_shm();
    probe_locks();
    probe_syslog();
    out("meta", "complete", "status=DONE");
    return 0;
}
