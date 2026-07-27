#include "probe.h"

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    /* A dead peer must never take the probe down mid-record. */
    signal(SIGPIPE, SIG_IGN);
    out("meta", "format", "wait_diff=1");
    probe_sleep();
    probe_locks();
    probe_fdwait();
    probe_jobctl();
    probe_cputime();
    probe_mqueue();
    probe_syslog();
    out("meta", "complete", "status=DONE");
    return 0;
}
