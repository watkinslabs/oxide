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
void *fopen(const char *path, const char *mode);
int   fclose(void *f);
unsigned long fwrite(const void *p, unsigned long sz, unsigned long n, void *f);
char *fgets(char *buf, int size, void *f);
void  rewind(void *f);
int   fscanf(void *f, const char *fmt, ...);
char *getenv(const char *name);
int   setenv(const char *name, const char *value, int overwrite);
int   strcmp(const char *a, const char *b);
int   atexit(void (*fn)(void));
int   fork(void);
int   execvp(const char *file, char *const argv[]);
int   waitpid(int pid, int *status, int options);
int   getppid(void);
void  _exit(int code);
int   pipe(int fds[2]);
long  read(int fd, void *buf, unsigned long n);
int   mkdir(const char *path, unsigned mode);
int   rmdir(const char *path);
char *getcwd(char *buf, unsigned long size);
int   stat(const char *path, void *buf);

static void on_exit_handler(void) {
    static const char m[] = "atexit-ok\n";
    write(1, m, sizeof(m) - 1);
}

int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;
    atexit(on_exit_handler);
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

    /* file round-trip: write then read back via fgets + fscanf */
    void *wf = fopen("/tmp/oxide_g6c.txt", "w");
    if (!wf) return 9;
    const char *line = "xyz 314\n";
    if (fwrite(line, 1, 8, wf) != 8) return 10;
    fclose(wf);
    void *rf = fopen("/tmp/oxide_g6c.txt", "r");
    if (!rf) return 11;
    char rb[32];
    if (!fgets(rb, sizeof rb, rf)) return 12;
    if (memcmp(rb, "xyz 314\n", 8) != 0) return 13;
    rewind(rf);
    char word[8]; int num = 0;
    if (fscanf(rf, "%s %d", word, &num) != 2) return 14;
    if (memcmp(word, "xyz", 4) != 0 || num != 314) return 15;
    fclose(rf);

    /* process: fork + execvp(/bin/true-ish) + waitpid */
    if (getppid() <= 0) return 18;
    int pid = fork();
    if (pid < 0) return 19;
    if (pid == 0) {
        char *av[] = { "true", 0 };
        execvp("true", av);
        _exit(127); /* exec failed */
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return 20;
    if (((st & 0x7f) != 0) || (((st >> 8) & 0xff) != 0)) return 21; /* child exit 0 */

    /* fds: pipe write/read round-trip */
    int p[2];
    if (pipe(p) != 0) return 22;
    if (write(p[1], "Z", 1) != 1) return 23;
    char pc = 0;
    if (read(p[0], &pc, 1) != 1 || pc != 'Z') return 24;
    close(p[0]); close(p[1]);

    /* fs: mkdir/rmdir + getcwd */
    rmdir("/tmp/oxide_g8b"); /* ignore if absent */
    if (mkdir("/tmp/oxide_g8b", 0755) != 0) return 25;
    if (rmdir("/tmp/oxide_g8b") != 0) return 26;
    char cwd[256];
    if (!getcwd(cwd, sizeof cwd)) return 27;

    /* stat: /proc/self/exe is a regular file with size > 0 (x86_64 offsets) */
    char stbuf[144];
    if (stat("/proc/self/exe", stbuf) != 0) return 28;
    unsigned smode = *(unsigned *)(stbuf + 24); /* st_mode @24 */
    long ssize = *(long *)(stbuf + 48);          /* st_size @48 */
    if (ssize <= 0) return 29;
    if ((smode & 0170000) != 0100000) return 30; /* S_ISREG */

    /* env: setenv then getenv round-trip */
    if (setenv("OXIDE_G7C", "yes", 1) != 0) return 16;
    char *ev = getenv("OXIDE_G7C");
    if (!ev || strcmp(ev, "yes") != 0) return 17;

    printf("%s (k=%d) scan=%d,%d file=%s/%d env=%s\n", buf, k, a, b, word, num, ev);
    puts("hello from oxide-libc");
    return 0;
}
