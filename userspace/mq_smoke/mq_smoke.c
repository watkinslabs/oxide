// /bin/mq_smoke — verifies kernel POSIX MQ priority-ordered
// records (B16: posix_mq.rs replaces the tmpfs-FIFO lie).
//
// Test: parent opens an MQ, forks. Child sends two messages with
// different priorities (low first, then high). Parent receives
// twice; first receive must return the high-priority message
// (PRIO 10), second must return the low (PRIO 1). If kernel
// were FIFO-only, parent would get them in send order → FAIL.

/* F152-1: real musl crt1 — no shim */
#include <unistd.h>
#include <fcntl.h>
#include <mqueue.h>
#include <sys/wait.h>
#include <string.h>

#define MQ_NAME "/oxide_mq_smoke"
#define MSG_HI "hi"
#define MSG_LO "lo"

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;

    struct mq_attr attr = { 0 };
    attr.mq_maxmsg  = 4;
    attr.mq_msgsize = 64;
    mqd_t mq = mq_open(MQ_NAME, O_CREAT | O_RDWR, 0666, &attr);
    if (mq < 0) {
        write(2, "mq_smoke: mq_open fail\n", 23);
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        write(2, "mq_smoke: fork fail\n", 20);
        mq_unlink(MQ_NAME);
        return 1;
    }

    if (pid == 0) {
        // Send LOW then HIGH; high must come back first.
        mq_send(mq, MSG_LO, sizeof(MSG_LO) - 1, 1);
        mq_send(mq, MSG_HI, sizeof(MSG_HI) - 1, 10);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);

    char buf[64];
    unsigned int prio1 = 0, prio2 = 0;
    long n1 = mq_receive(mq, buf, sizeof(buf), &prio1);
    int hi_first = (n1 == 2) && (prio1 == 10) && (memcmp(buf, MSG_HI, 2) == 0);

    long n2 = mq_receive(mq, buf, sizeof(buf), &prio2);
    int lo_second = (n2 == 2) && (prio2 == 1) && (memcmp(buf, MSG_LO, 2) == 0);

    mq_close(mq);
    mq_unlink(MQ_NAME);

    if (hi_first && lo_second) {
        write(1, "mq_smoke: PASS\n", 15);
        return 0;
    } else {
        write(1, "mq_smoke: FAIL\n", 15);
        return 1;
    }
}
