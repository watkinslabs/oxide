// /bin/msg_smoke — verifies kernel SysV msg blocking semantics
// (B15: msgsnd/msgrcv block via WaitList instead of EAGAIN).
//
// Test: parent forks; child sends a typed message; parent receives.
// Race-tolerant: if parent's msgrcv runs first it blocks until
// child's msgsnd; if child runs first the message is queued and
// parent's msgrcv gets it without blocking. Either path → PASS.

/* F152-1: real musl crt1 — no shim */
#include <unistd.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <string.h>

#define PAYLOAD "hello-from-child"

struct mbuf {
    long mtype;
    char data[64];
};

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;

    int msqid = msgget(0 /*IPC_PRIVATE*/, 0666 | 01000 /*IPC_CREAT*/);
    if (msqid < 0) {
        write(2, "msg_smoke: msgget fail\n", 23);
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        write(2, "msg_smoke: fork fail\n", 21);
        return 1;
    }

    if (pid == 0) {
        struct mbuf m;
        m.mtype = 7;
        memcpy(m.data, PAYLOAD, sizeof(PAYLOAD) - 1);
        msgsnd(msqid, &m, sizeof(PAYLOAD) - 1, 0);
        _exit(0);
    }

    struct mbuf got;
    long n = msgrcv(msqid, &got, sizeof(got.data), 7, 0);

    int status;
    waitpid(pid, &status, 0);

    int ok = (n == (long)(sizeof(PAYLOAD) - 1))
          && (got.mtype == 7)
          && (memcmp(got.data, PAYLOAD, sizeof(PAYLOAD) - 1) == 0);

    msgctl(msqid, 0 /*IPC_RMID*/, 0);

    if (ok) {
        write(1, "msg_smoke: PASS\n", 16);
        return 0;
    } else {
        write(1, "msg_smoke: FAIL\n", 16);
        return 1;
    }
}
