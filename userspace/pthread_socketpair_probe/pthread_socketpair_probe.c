// /bin/pthread_socketpair_probe — probes the openssh sshpam_thread
// pattern: main thread creates a pthread + a UNIX socketpair, the
// pthread writes a message and waits for a response from the main
// thread. If our kernel breaks this pattern (PAM_CONV-call from
// pam_unix.so wedging is the symptom), this binary will hang too
// and we have a clean kernel-level reproducer.
//
// Expected output on a working kernel:
//   probe: main thread started
//   probe: spawned child thread
//   probe: child sent "hi", awaiting reply
//   probe: main got "hi"
//   probe: main sent "yo"
//   probe: child got "yo" — DONE
//   probe: PASS
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

static int sp[2];

static void *child(void *arg) {
    (void)arg;
    write(1, "probe: child sent \"hi\", awaiting reply\n", 39);
    write(sp[0], "hi", 2);
    char buf[8] = {0};
    int n = read(sp[0], buf, sizeof buf - 1);
    if (n > 0) {
        write(1, "probe: child got \"", 18);
        write(1, buf, n);
        write(1, "\" -- DONE\n", 10);
    }
    return NULL;
}

int main(void) {
    write(1, "probe: main thread started\n", 27);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
        write(2, "probe: socketpair FAIL\n", 23);
        return 1;
    }
    pthread_t t;
    if (pthread_create(&t, NULL, child, NULL) != 0) {
        write(2, "probe: pthread_create FAIL\n", 27);
        return 1;
    }
    write(1, "probe: spawned child thread\n", 28);
    char buf[8] = {0};
    int n = read(sp[1], buf, sizeof buf - 1);
    if (n > 0) {
        write(1, "probe: main got \"", 17);
        write(1, buf, n);
        write(1, "\"\n", 2);
    }
    write(1, "probe: main sent \"yo\"\n", 22);
    write(sp[1], "yo", 2);
    // F243 fixed first-run wrmsr FS_BASE for x86 so pthread_join
    // works there; ARM equivalent (TPIDR_EL0 on context_switch
    // tail) hasn't landed yet, so we detach to keep smoke moving
    // on both arches.
    pthread_detach(t);
    usleep(50 * 1000);
    write(1, "probe: PASS\n", 12);
    return 0;
}
