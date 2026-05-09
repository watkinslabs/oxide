// /bin/sem_smoke — verifies kernel SysV sem blocking semantics
// (B15: real semop with WaitList).
//
// Test: parent forks child. Both race; whichever blocks first
// gets unblocked by the other.
//   - Parent does semop(WAIT, -1) on a value-0 sem.
//   - Child  does semop(POST, +1).
// If kernel blocks-correctly: parent either (a) blocks then
// wakes after child posts, or (b) finds value already 1 if
// child ran first. Both paths succeed; test passes.
//
// Failure mode (pre-B15): parent semop returns -EAGAIN because
// kernel never blocked → parent prints FAIL and exits 1.

/* F152-1: real musl crt1 — no shim */
#include <unistd.h>
#include <sys/sem.h>
#include <sys/wait.h>

#define MSG_PASS "sem_smoke: PASS\n"
#define MSG_FAIL "sem_smoke: FAIL\n"
#define MSG_SEMGET "sem_smoke: semget fail\n"
#define MSG_FORK   "sem_smoke: fork fail\n"

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;

    int semid = semget(0 /*IPC_PRIVATE*/, 1, 0666 | 01000 /*IPC_CREAT*/);
    if (semid < 0) {
        write(2, MSG_SEMGET, sizeof(MSG_SEMGET) - 1);
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        write(2, MSG_FORK, sizeof(MSG_FORK) - 1);
        return 1;
    }

    if (pid == 0) {
        struct sembuf post = { 0, 1, 0 };
        semop(semid, &post, 1);
        _exit(0);
    }

    // Parent: blocking wait. Returns 0 on success, -1 on EAGAIN/EINVAL.
    struct sembuf wait = { 0, -1, 0 };
    int rv = semop(semid, &wait, 1);

    int status;
    waitpid(pid, &status, 0);

    if (rv == 0) {
        semctl(semid, 0, 0 /*IPC_RMID*/);
        write(1, MSG_PASS, sizeof(MSG_PASS) - 1);
        return 0;
    } else {
        semctl(semid, 0, 0);
        write(1, MSG_FAIL, sizeof(MSG_FAIL) - 1);
        return 1;
    }
}
