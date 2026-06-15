/* G2/G3 smoke for oxide-libc (docs/59§6): exercises the entry path
 * _start -> __libc_start_main (auxv AT_RANDOM canary reseed) -> main and
 * the core syscall wrappers (open/close/getpid/write), linked against
 * our libc.a with -nostdlib. No libc headers (we are the libc); declare
 * the symbols we call. Built -fno-stack-protector until the global-guard
 * read path is wired (G3 seeds the guard; using it needs G11 TLS). */
long write(int fd, const void *buf, unsigned long n);
int  open(const char *path, int flags, unsigned mode);
int  close(int fd);
int  getpid(void);

int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;
    int fd = open("/dev/null", 0 /*O_RDONLY*/, 0);
    if (fd < 0) return 2;
    if (close(fd) != 0) return 3;
    if (getpid() <= 0) return 4;
    static const char msg[] = "hello from oxide-libc\n";
    write(1, msg, sizeof(msg) - 1);
    return 0;
}
