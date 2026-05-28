// /bin/exit_test — kernel wait4/wstatus smoke. Verifies:
//   A) fork + child-return-42         → wstat == 0x2a00 (42 << 8)
//   B) fork + execve "/bin/true"      → wstat == 0x0000
//   C) fork + execve "/bin/false"     → wstat == 0x0100  (1 << 8)
// Catches kernel wait4 / sys_exit code-encoding regressions. Used
// during F232 to prove wait4 is correct kernel-side; busybox-ash
// `$?=255` issue is shell-side and tracked as task #12.
#include <unistd.h>
#include <sys/wait.h>

static void write_hex(const char *tag, int v) {
    char buf[32];
    int len = 0;
    while (*tag) buf[len++] = *tag++;
    buf[len++] = '=';
    for (int i = 7; i >= 0; i--) {
        int n = (v >> (i*4)) & 0xf;
        buf[len++] = n < 10 ? '0' + n : 'a' + n - 10;
    }
    buf[len++] = '\n';
    write(1, buf, len);
}

int main(void) {
    pid_t pid; int w;
    pid = fork();
    if (pid == 0) return 42;
    w = 0xCAFE; wait4(pid, &w, 0, 0); write_hex("A", w);

    pid = fork();
    if (pid == 0) {
        const char *argv[] = {"true", 0};
        execve("/bin/true", (char *const*)argv, 0);
        _exit(127);
    }
    w = 0xCAFE; wait4(pid, &w, 0, 0); write_hex("B", w);

    pid = fork();
    if (pid == 0) {
        const char *argv[] = {"false", 0};
        execve("/bin/false", (char *const*)argv, 0);
        _exit(127);
    }
    w = 0xCAFE; wait4(pid, &w, 0, 0); write_hex("C", w);
    return 0;
}
