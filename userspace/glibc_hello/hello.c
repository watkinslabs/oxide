/* G2/G3/G6 smoke for oxide-libc (docs/59§6): entry path + core syscalls
 * + stdio. Linked against our libc.a with -nostdlib; we declare the
 * symbols we call (we are the libc). -fno-stack-protector until the
 * global-guard read path is wired (G3 seeds it; using it needs G11 TLS). */
long write(int fd, const void *buf, unsigned long n);
int  open(const char *path, int flags, unsigned mode);
int  close(int fd);
int  getpid(void);
int  snprintf(char *s, unsigned long n, const char *fmt, ...);
int  printf(const char *fmt, ...);
int  puts(const char *s);
int  memcmp(const void *a, const void *b, unsigned long n);
int  sscanf(const char *s, const char *fmt, ...);

int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;
    int fd = open("/dev/null", 0 /*O_RDONLY*/, 0);
    if (fd < 0) return 2;
    if (close(fd) != 0) return 3;
    if (getpid() <= 0) return 4;

    char buf[64];
    int k = snprintf(buf, sizeof buf, "n=%d hex=%#x s=%s", 42, 255, "ok");
    const char *want = "n=42 hex=0xff s=ok";
    if (k != 18) return 5;
    if (memcmp(buf, want, 18) != 0) return 6;

    int a = 0, b = 0;
    if (sscanf("42 -7", "%d %d", &a, &b) != 2) return 7;
    if (a != 42 || b != -7) return 8;

    printf("%s (k=%d) scan=%d,%d\n", buf, k, a, b);
    puts("hello from oxide-libc");
    return 0;
}
