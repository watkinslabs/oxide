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
void *opendir(const char *name);
void *readdir(void *d);
int   closedir(void *d);
int   glob(const char *pat, int flags, void *errfn, void *pglob);
void  globfree(void *pglob);
typedef void (*sighandler_t)(int);
sighandler_t signal(int sig, sighandler_t handler);
int   raise(int sig);

static volatile int g_sigflag = 0;
static void on_usr1(int s) { (void)s; g_sigflag = 1; }

typedef unsigned long pthread_t;
int pthread_create(pthread_t *t, const void *attr, void *(*start)(void *), void *arg);
int pthread_join(pthread_t t, void **retval);
static volatile int g_shared = 0;
static void *worker(void *a) { (void)a; for (int i = 0; i < 1000; i++) g_shared++; return (void *)42; }

typedef union { unsigned char __b[40]; long __a; } pthread_mutex_t;
int pthread_mutex_init(pthread_mutex_t *m, const void *attr);
int pthread_mutex_lock(pthread_mutex_t *m);
int pthread_mutex_unlock(pthread_mutex_t *m);
static pthread_mutex_t g_mtx; /* zero-init == NORMAL mutex */
static unsigned long g_count = 0;
static void *counter_worker(void *a) {
    (void)a;
    for (int i = 0; i < 10000; i++) { pthread_mutex_lock(&g_mtx); g_count++; pthread_mutex_unlock(&g_mtx); }
    return 0;
}

/* G11c: cond / rwlock / once / TLS-keys */
typedef union { unsigned char b[48]; long a; } pthread_cond_t;
int pthread_cond_init(pthread_cond_t *c, const void *attr);
int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m);
int pthread_cond_signal(pthread_cond_t *c);
static pthread_cond_t g_cv;
static pthread_mutex_t g_cvm;
static volatile int g_ready = 0, g_woke = 0;
static void *cv_worker(void *a) {
    (void)a;
    pthread_mutex_lock(&g_cvm);
    while (!g_ready) pthread_cond_wait(&g_cv, &g_cvm);
    g_woke = 1;
    pthread_mutex_unlock(&g_cvm);
    return 0;
}

typedef union { unsigned char b[56]; long a; } pthread_rwlock_t;
int pthread_rwlock_init(pthread_rwlock_t *l, const void *attr);
int pthread_rwlock_rdlock(pthread_rwlock_t *l);
int pthread_rwlock_wrlock(pthread_rwlock_t *l);
int pthread_rwlock_unlock(pthread_rwlock_t *l);
static pthread_rwlock_t g_rw;
static unsigned long g_rwcount = 0;
static void *rw_worker(void *a) {
    (void)a;
    for (int i = 0; i < 1000; i++) { pthread_rwlock_wrlock(&g_rw); g_rwcount++; pthread_rwlock_unlock(&g_rw); }
    return 0;
}

typedef int pthread_once_t;
int pthread_once(pthread_once_t *o, void (*init)(void));
static pthread_once_t g_once = 0; /* PTHREAD_ONCE_INIT */
static volatile int g_once_count = 0;
static void once_init(void) { g_once_count++; }
static void *once_worker(void *a) { (void)a; pthread_once(&g_once, once_init); return 0; }

typedef unsigned int pthread_key_t;
int pthread_key_create(pthread_key_t *k, void (*dtor)(void *));
void *pthread_getspecific(pthread_key_t k);
int pthread_setspecific(pthread_key_t k, const void *v);
static pthread_key_t g_key;
static volatile int g_key_thread_ok = 0;

/* G12f: per-thread errno isolation. Both threads set a distinct errno via a
 * failing call, sync so both have set, then re-read — each must still see its
 * own value (would be clobbered if errno were a single global). */
extern int *__errno_location(void);
#define ERRNO (*__errno_location())
static volatile int g_eb = 0;
static void *errno_worker_a(void *a) {
    (void)a;
    open("/no/such/path/a", 0, 0);          /* -> ENOENT (2) */
    __sync_fetch_and_add(&g_eb, 1);
    while (g_eb < 2) { }
    return (void *)(long)ERRNO;
}
static void *errno_worker_b(void *a) {
    (void)a;
    close(-1);                               /* -> EBADF (9) */
    __sync_fetch_and_add(&g_eb, 1);
    while (g_eb < 2) { }
    return (void *)(long)ERRNO;
}

static void *key_worker(void *a) {
    (void)a;
    pthread_setspecific(g_key, (void *)0x222);
    if (pthread_getspecific(g_key) == (void *)0x222) g_key_thread_ok = 1;
    return 0;
}

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

    /* dirent: opendir(".")/readdir lists entries incl "." */
    void *dp = opendir(".");
    if (!dp) return 31;
    int found_dot = 0, dcount = 0;
    void *de;
    while ((de = readdir(dp))) {
        char *nm = (char *)de + 19; /* d_name @19 */
        if (nm[0] == '.' && nm[1] == 0) found_dot = 1;
        if (++dcount > 100000) break;
    }
    closedir(dp);
    if (!found_dot || dcount < 2) return 32;

    /* glob: /dev/n* matches at least /dev/null */
    char gbuf[72];
    if (glob("/dev/n*", 0, 0, gbuf) != 0) return 33;
    unsigned long gpathc = *(unsigned long *)(gbuf + 0);
    if (gpathc < 1) return 34;
    globfree(gbuf);

    /* signal: install SIGUSR1 handler, raise it, verify it ran + returned
       (exercises the rt_sigreturn restorer) */
    if (signal(10 /*SIGUSR1*/, on_usr1) == (sighandler_t)-1) return 35;
    if (raise(10) != 0) return 36;
    if (g_sigflag != 1) return 37;

    /* time: monotonic clock nondecreasing + nanosleep 1ms returns 0 */
    long ts1[2] = {0, 0}, ts2[2] = {0, 0};
    int clock_gettime(int, void *);
    int nanosleep(const void *, void *);
    if (clock_gettime(1 /*MONOTONIC*/, ts1) != 0) return 38;
    long req[2] = {0, 1000000}; /* 1ms */
    if (nanosleep(req, 0) != 0) return 39;
    if (clock_gettime(1, ts2) != 0) return 40;
    if (ts2[0] < ts1[0] || (ts2[0] == ts1[0] && ts2[1] < ts1[1])) return 41;

    /* pthread: create a worker, join it, check shared state + retval
       (exercises the clone child-entry trampoline + CHILD_CLEARTID join) */
    pthread_t th;
    if (pthread_create(&th, 0, worker, 0) != 0) return 42;
    void *rv = 0;
    if (pthread_join(th, &rv) != 0) return 43;
    if (g_shared != 1000) return 44;
    if (rv != (void *)42) return 45;

    /* pthread_mutex: 4 threads each increment a shared counter 10000x under
       a NORMAL mutex; join all; assert exactly 40000 (real mutual exclusion) */
    pthread_mutex_init(&g_mtx, 0);
    pthread_t mt[4];
    for (int i = 0; i < 4; i++) if (pthread_create(&mt[i], 0, counter_worker, 0) != 0) return 46;
    for (int i = 0; i < 4; i++) if (pthread_join(mt[i], 0) != 0) return 47;
    if (g_count != 40000) return 48;

    /* pthread_cond: worker waits on a predicate; main sets it + signals */
    pthread_mutex_init(&g_cvm, 0);
    pthread_cond_init(&g_cv, 0);
    pthread_t cvt;
    if (pthread_create(&cvt, 0, cv_worker, 0) != 0) return 49;
    pthread_mutex_lock(&g_cvm);
    g_ready = 1;
    pthread_mutex_unlock(&g_cvm);
    pthread_cond_signal(&g_cv);
    if (pthread_join(cvt, 0) != 0) return 50;
    if (g_woke != 1) return 51;

    /* pthread_rwlock: 4 writers each increment 1000x under wrlock == 4000 */
    pthread_rwlock_init(&g_rw, 0);
    pthread_rwlock_rdlock(&g_rw); pthread_rwlock_unlock(&g_rw); /* basic rd path */
    pthread_t rwt[4];
    for (int i = 0; i < 4; i++) if (pthread_create(&rwt[i], 0, rw_worker, 0) != 0) return 52;
    for (int i = 0; i < 4; i++) if (pthread_join(rwt[i], 0) != 0) return 53;
    if (g_rwcount != 4000) return 54;

    /* pthread_once: init runs exactly once across main + 4 threads */
    pthread_once(&g_once, once_init);
    pthread_t ot[4];
    for (int i = 0; i < 4; i++) if (pthread_create(&ot[i], 0, once_worker, 0) != 0) return 55;
    for (int i = 0; i < 4; i++) if (pthread_join(ot[i], 0) != 0) return 56;
    if (g_once_count != 1) return 57;

    /* TLS keys: per-thread isolation (main keeps 0x111, thread sets 0x222) */
    if (pthread_key_create(&g_key, 0) != 0) return 58;
    if (pthread_setspecific(g_key, (void *)0x111) != 0) return 59;
    pthread_t kt;
    if (pthread_create(&kt, 0, key_worker, 0) != 0) return 60;
    if (pthread_join(kt, 0) != 0) return 61;
    if (!g_key_thread_ok) return 62;
    if (pthread_getspecific(g_key) != (void *)0x111) return 63;

    /* per-thread errno isolation: each thread keeps its own errno */
    pthread_t et[2]; void *ea = 0, *eb = 0;
    if (pthread_create(&et[0], 0, errno_worker_a, 0) != 0) return 64;
    if (pthread_create(&et[1], 0, errno_worker_b, 0) != 0) return 64;
    pthread_join(et[0], &ea);
    pthread_join(et[1], &eb);
    if ((long)ea != 2) return 65;   /* worker A still sees ENOENT */
    if ((long)eb != 9) return 66;   /* worker B still sees EBADF */

    /* net: socketpair(AF_UNIX,SOCK_STREAM) write/read round-trip */
    int socketpair(int domain, int type, int protocol, int sv[2]);
    int sv[2];
    if (socketpair(1 /*AF_UNIX*/, 1 /*SOCK_STREAM*/, 0, sv) != 0) return 67;
    if (write(sv[1], "Z", 1) != 1) return 68;
    char sc = 0;
    if (read(sv[0], &sc, 1) != 1 || sc != 'Z') return 69;
    close(sv[0]); close(sv[1]);

    /* nss: getpwuid(0) reads /etc/passwd → uid 0 is "root" */
    struct pw_min { char *pw_name, *pw_passwd; unsigned pw_uid, pw_gid; char *pw_gecos, *pw_dir, *pw_shell; };
    struct pw_min *getpwuid(unsigned uid);
    struct pw_min *pw = getpwuid(0);
    if (!pw) return 70;
    if (strcmp(pw->pw_name, "root") != 0) return 71;

    /* env: setenv then getenv round-trip */
    if (setenv("OXIDE_G7C", "yes", 1) != 0) return 16;
    char *ev = getenv("OXIDE_G7C");
    if (!ev || strcmp(ev, "yes") != 0) return 17;

    printf("%s (k=%d) scan=%d,%d file=%s/%d env=%s\n", buf, k, a, b, word, num, ev);
    puts("hello from oxide-libc");
    return 0;
}
