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
    probe_sleep();
    probe_fdwait();
    probe_jobctl();
    probe_cputime();
    probe_mqueue();
    probe_locks();
    probe_syslog();
    out("meta", "complete", "status=DONE");
    return 0;
}
