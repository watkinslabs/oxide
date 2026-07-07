// /bin/signalfd_probe — G8 guard: signalfd(2) must (a) update the mask of an
// EXISTING fd (Linux re-arm), and (b) fill the full signalfd_siginfo, not just
// ssi_signo. Pre-G8 the mask-update was a no-op and read zeroed everything but
// ssi_signo — so systemd's SIGCHLD-via-signalfd never saw the child pid/status.
//
// Flow: block SIGCHLD; create a signalfd armed for a DIFFERENT signal (SIGUSR1);
// then signalfd(fd, {SIGCHLD}) to UPDATE its mask; fork a child that exits 42;
// read the signalfd and assert ssi_signo==SIGCHLD (proves the mask update took)
// AND ssi_pid==child && ssi_status==42 && ssi_code==CLD_EXITED (proves the
// siginfo fill). Raw syscalls so the mask is an unambiguous u64 bitmask.

#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define PASS "signalfd_probe: PASS\n"
#define FAIL "signalfd_probe: FAIL\n"

#define SIG_SIGCHLD 17
#define SIG_SIGUSR1 10
#ifndef CLD_EXITED
#define CLD_EXITED  1
#endif

// struct signalfd_siginfo (128 bytes) — the fields we check, by offset.
struct sfd_si {
    uint32_t ssi_signo;   // 0
    int32_t  ssi_errno;   // 4
    int32_t  ssi_code;    // 8
    uint32_t ssi_pid;     // 12
    uint32_t ssi_uid;     // 16
    int32_t  ssi_fd;      // 20
    uint32_t ssi_tid;     // 24
    uint32_t ssi_band;    // 28
    uint32_t ssi_overrun; // 32
    uint32_t ssi_trapno;  // 36
    int32_t  ssi_status;  // 40
    int32_t  ssi_int;     // 44
    uint64_t ssi_ptr;     // 48
    uint8_t  pad[128 - 56];
};

int main(void) {
    // Block SIGCHLD so it stays pending for the signalfd instead of being
    // default-ignored / delivered.
    uint64_t block = 1ULL << (SIG_SIGCHLD - 1);
    syscall(SYS_rt_sigprocmask, SIG_BLOCK, &block, (void *)0, 8);

    // Create the signalfd armed for SIGUSR1 (NOT SIGCHLD) — proves the update.
    uint64_t m_usr1 = 1ULL << (SIG_SIGUSR1 - 1);
    int sfd = (int)syscall(SYS_signalfd4, -1, &m_usr1, 8, 0);
    if (sfd < 0) { write(1, FAIL, sizeof FAIL - 1); return 1; }

    // Update the mask in place to SIGCHLD (Linux re-arm). Pre-G8 this no-op'd.
    uint64_t m_chld = 1ULL << (SIG_SIGCHLD - 1);
    if ((int)syscall(SYS_signalfd4, sfd, &m_chld, 8, 0) != sfd) {
        write(1, FAIL, sizeof FAIL - 1); return 1;
    }

    pid_t pid = fork();
    if (pid == 0) { _exit(42); }
    if (pid < 0) { write(1, FAIL, sizeof FAIL - 1); return 1; }

    // The signalfd read is non-blocking (returns EAGAIN until SIGCHLD is
    // pending); yield so the child can run+exit on a UP kernel, then retry.
    struct sfd_si si;
    memset(&si, 0, sizeof si);
    ssize_t n = -1;
    for (int tries = 0; tries < 100000; tries++) {
        n = read(sfd, &si, sizeof si);
        if (n == 128) break;
        sched_yield();
    }
    (void)waitpid(pid, 0, 0);

    if (n == 128
        && si.ssi_signo == SIG_SIGCHLD   // mask update delivered SIGCHLD
        && si.ssi_pid == (uint32_t)pid   // siginfo: child pid
        && si.ssi_status == 42           // siginfo: exit status
        && si.ssi_code == CLD_EXITED) {  // siginfo: CLD_EXITED
        write(1, PASS, sizeof PASS - 1);
        return 0;
    }
    write(1, FAIL, sizeof FAIL - 1);
    return 1;
}
