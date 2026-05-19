// /bin/usleep_smoke — verifies usleep + write progress (B47).
//
// getty hangs at usleep(100ms) → no write before stuck. This
// probe isolates the same pattern: usleep(100ms), then write.
// If the kernel hangs here too, nanosleep is broken; if it
// works, getty has a different issue.

#include <unistd.h>

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    write(1, "usleep_smoke: pre\n", 18);
    usleep(100 * 1000);
    write(1, "usleep_smoke: PASS\n", 19);
    return 0;
}
