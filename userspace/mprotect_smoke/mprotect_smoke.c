// /bin/mprotect_smoke — verifies kernel per-PTE mprotect (F14).
//
// Test layout:
//   - Parent forks a child.
//   - Child: mmap RW, write a byte, mprotect to PROT_READ, then
//     write again. Post-F14 the kernel flips the PTE.W bit, the
//     write traps, the kernel delivers SIGSEGV (= exit code 11).
//     Pre-F14 the write succeeded silently → child exits 0.
//   - Parent: waitpid; PASS only if status reports SIGSEGV.
//
// We do the fork/wait dance because the kernel doesn't yet
// dispatch SIGSEGV to a user handler — it just terminates the
// task with status=signal. Detection from the parent works
// without that machinery.

/* F152-1: real musl crt1 — no shim */
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define PASS_MSG "mprotect_smoke: PASS\n"
#define FAIL_MSG "mprotect_smoke: FAIL\n"

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;

    pid_t pid = fork();
    if (pid < 0) {
        write(2, "mprotect_smoke: fork fail\n", 26);
        return 1;
    }
    if (pid == 0) {
        // Child path — provoke the protection fault.
        void* page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED) _exit(2);
        *(volatile char*)page = 0x42;            // demand-fault in
        if (mprotect(page, 4096, PROT_READ) != 0) _exit(3);
        // The next write must trap. Pre-F14 it silently succeeds
        // and we exit 0 — parent then reads "no signal" and
        // emits FAIL.
        *(volatile char*)page = 0x99;
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    // POSIX wstatus encoding: bits 0..6 = signal that killed the
    // child (0 if normal exit). 11 = SIGSEGV.
    int sig = status & 0x7f;
    if (sig == 11) {
        write(1, PASS_MSG, sizeof(PASS_MSG) - 1);
        return 0;
    }
    write(1, FAIL_MSG, sizeof(FAIL_MSG) - 1);
    return 1;
}
