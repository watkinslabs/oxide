// /bin/ptrace_smoke — verifies kernel ptrace PEEK reads target
// memory for real (B16: foreign-mm read via translate_4k_at_root).
//
// Test: parent forks; child carries a known string at a known
// address (a global) and spins. Parent ATTACHes, PEEKs the
// global, verifies bytes match. Failure mode (pre-B16): PEEK
// returned 0 → mismatch → FAIL.
//
// Race: child must be alive when parent PEEKs. Child spins on
// a sentinel volatile that the parent never clears, so it stays
// runnable until parent SIGKILLs it via PTRACE_KILL.

#include "../shared/oxide_start.h"
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

// 8-byte payload aligned so PEEK reads it as a single word.
__attribute__((aligned(8)))
volatile char target_payload[8] = { 'O','X','I','D','E','!','!','\n' };
volatile int  child_done = 0;

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;

    pid_t pid = fork();
    if (pid < 0) {
        write(2, "ptrace_smoke: fork fail\n", 24);
        return 1;
    }

    if (pid == 0) {
        // Child: spin until killed. Reads the target_payload to
        // ensure the page is faulted in.
        for (int i = 0; i < 1024 && !child_done; i++) {
            volatile char c = target_payload[i & 7];
            (void)c;
        }
        _exit(0);
    }

    long rv = ptrace(PTRACE_ATTACH, pid, 0, 0);
    if (rv < 0) {
        write(2, "ptrace_smoke: ATTACH fail\n", 26);
        ptrace(PTRACE_KILL, pid, 0, 0);
        waitpid(pid, 0, 0);
        return 1;
    }

    // PEEKDATA returns the 8 bytes at the supplied address. Address
    // is the same in the child because static-PIE base is shared
    // post-fork (CoW; data section unchanged).
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, (void*)target_payload, 0);
    int peek_ok = (errno == 0)
               && (memcmp(&word, (const void*)target_payload, 8) == 0);

    ptrace(PTRACE_KILL, pid, 0, 0);
    waitpid(pid, 0, 0);

    if (peek_ok) {
        write(1, "ptrace_smoke: PASS\n", 19);
        return 0;
    } else {
        write(1, "ptrace_smoke: FAIL\n", 19);
        return 1;
    }
}
