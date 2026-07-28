/* FPU/SIMD state across signal delivery.
 *
 * Linux saves the interrupted thread's FPU/SIMD registers into the signal
 * frame (x86_64 `copy_fpstate_to_sigframe` → `uc_mcontext.fpstate`; arm64
 * `preserve_fpsimd_context` → an `FPSIMD_MAGIC` record in
 * `uc_mcontext.__reserved`) and reloads them at `rt_sigreturn`. Without that,
 * a handler calling ANY glibc string/memory routine — all of them SIMD —
 * destroys whatever the interrupted code was computing, silently, at an
 * arbitrary point. B1466 found oxide writing `fpstate = 0` on x86_64 and an
 * empty record chain on arm64 (a frame Linux's own `restore_sigframe`
 * rejects with -EINVAL).
 *
 * Both cases below are deterministic: the probe spins in an asm loop holding
 * a known pattern in SIMD registers until the handler sets a flag, so the
 * signal always lands with the pattern LIVE in registers and no timing
 * margin is involved. The register load, the spin and the read-back are one
 * asm block, so the compiler cannot spill the pattern to memory and hide the
 * defect.
 *
 * The SIMD register access is necessarily per-arch — you cannot observe SIMD
 * preservation without naming SIMD registers — but every syscall here is an
 * ordinary glibc entry point.
 */
#include "probe.h"

/* Callee-clobberable vector registers on both arches, and the byte width of
 * the pattern they hold. x86_64 xmm4..xmm7 / aarch64 v4..v7. */
#define VREGS      4
#define VREG_BYTES 16
#define PAT_BYTES  (VREGS * VREG_BYTES)

/* Big enough that glibc's memcpy/memset take their SIMD paths. */
#define SCRATCH_BYTES 4096

/* `struct _aarch64_ctx` / `fpsimd_context` from
 * arch/arm64/include/uapi/asm/sigcontext.h. Declared locally: including
 * <asm/sigcontext.h> next to <sys/ucontext.h> redefines struct sigcontext. */
#define PROBE_FPSIMD_MAGIC 0x46508001u

struct probe_ctx_head { uint32_t magic; uint32_t size; };
struct probe_fpsimd_ctx {
    struct probe_ctx_head head;
    uint32_t fpsr;
    uint32_t fpcr;
    unsigned char vregs[32][16];
};

static volatile sig_atomic_t g_hit;
/* What the handler saw in the interrupted context's saved FP state. */
static int  g_uc_present;
static int  g_uc_live;
static unsigned char g_pattern[PAT_BYTES];
static unsigned char g_readback[PAT_BYTES];

/* A pattern the handler jams into the SIMD registers; must differ from
 * g_pattern in every byte so a missed restore cannot look like a match. */
static unsigned char g_clobber[PAT_BYTES];

static void fill(unsigned char *p, unsigned char seed) {
    for (int i = 0; i < PAT_BYTES; i++) p[i] = (unsigned char)(seed ^ (i * 7 + 1));
}

/* ---------------------------------------------------------------- per-arch */

/* Load `in` into the vector registers, spin until *flag, then store them to
 * `out`. The signal is delivered inside the spin, so the pattern is live in
 * registers at the moment of delivery. */
static void load_spin_store(const unsigned char *in, unsigned char *out,
                            volatile sig_atomic_t *flag) {
#if defined(__x86_64__)
    __asm__ __volatile__(
        "movdqu   0(%[in]), %%xmm4\n\t"
        "movdqu  16(%[in]), %%xmm5\n\t"
        "movdqu  32(%[in]), %%xmm6\n\t"
        "movdqu  48(%[in]), %%xmm7\n\t"
        "1:\n\t"
        "movl    (%[flag]), %%eax\n\t"
        "testl   %%eax, %%eax\n\t"
        "je      1b\n\t"
        "movdqu  %%xmm4,  0(%[out])\n\t"
        "movdqu  %%xmm5, 16(%[out])\n\t"
        "movdqu  %%xmm6, 32(%[out])\n\t"
        "movdqu  %%xmm7, 48(%[out])\n\t"
        :
        : [in] "r"(in), [out] "r"(out), [flag] "r"(flag)
        : "eax", "xmm4", "xmm5", "xmm6", "xmm7", "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__(
        "ldp  q4, q5, [%[in]]\n\t"
        "ldp  q6, q7, [%[in], #32]\n\t"
        "1:\n\t"
        "ldr  w9, [%[flag]]\n\t"
        "cbz  w9, 1b\n\t"
        "stp  q4, q5, [%[out]]\n\t"
        "stp  q6, q7, [%[out], #32]\n\t"
        :
        : [in] "r"(in), [out] "r"(out), [flag] "r"(flag)
        : "w9", "v4", "v5", "v6", "v7", "memory");
#else
#error "wait_diff sigfpu: unsupported architecture"
#endif
}

/* Overwrite the same vector registers from inside the handler. Explicit asm
 * rather than trusting a particular glibc memcpy implementation to touch
 * these exact registers — the point is a GUARANTEED clobber. */
static void clobber_vregs(const unsigned char *in) {
#if defined(__x86_64__)
    __asm__ __volatile__(
        "movdqu   0(%[in]), %%xmm4\n\t"
        "movdqu  16(%[in]), %%xmm5\n\t"
        "movdqu  32(%[in]), %%xmm6\n\t"
        "movdqu  48(%[in]), %%xmm7\n\t"
        : : [in] "r"(in) : "xmm4", "xmm5", "xmm6", "xmm7", "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__(
        "ldp  q4, q5, [%[in]]\n\t"
        "ldp  q6, q7, [%[in], #32]\n\t"
        : : [in] "r"(in) : "v4", "v5", "v6", "v7", "memory");
#endif
}

/* Locate the interrupted context's saved vector registers inside `uc`, or
 * NULL if the kernel saved none. This is the pointer x86 hardcoded to 0 and
 * the record chain arm64 left empty. */
static unsigned char *uc_vregs(ucontext_t *uc) {
#if defined(__x86_64__)
    fpregset_t fp = uc->uc_mcontext.fpregs;
    if (fp == NULL) return NULL;
    return (unsigned char *)&fp->_xmm[4];
#elif defined(__aarch64__)
    unsigned char *base = (unsigned char *)uc->uc_mcontext.__reserved;
    size_t off = 0, limit = sizeof(uc->uc_mcontext.__reserved);
    while (off + sizeof(struct probe_ctx_head) <= limit) {
        struct probe_ctx_head h;
        memcpy(&h, base + off, sizeof h);
        if (h.magic == 0) return NULL;                 /* terminator */
        if (h.size < sizeof h || off + h.size > limit) return NULL;
        if (h.magic == PROBE_FPSIMD_MAGIC) {
            if (h.size != sizeof(struct probe_fpsimd_ctx)) return NULL;
            return base + off + offsetof(struct probe_fpsimd_ctx, vregs[4]);
        }
        off += h.size;
    }
    return NULL;
#endif
}

/* ---------------------------------------------------------------- handler */

static void fpu_handler(int sig, siginfo_t *si, void *ctx) {
    (void)sig; (void)si;
    ucontext_t *uc = (ucontext_t *)ctx;
    unsigned char *saved = uc_vregs(uc);
    g_uc_present = saved != NULL;
    g_uc_live = saved != NULL && memcmp(saved, g_pattern, PAT_BYTES) == 0;

    /* Do what a real handler does: call SIMD-optimised glibc routines. */
    static unsigned char a[SCRATCH_BYTES], b[SCRATCH_BYTES];
    memset(a, 0x5a, sizeof a);
    memcpy(b, a, sizeof b);
    if (memcmp(a, b, sizeof a) != 0) _exit(70);
    /* ...and guarantee the specific registers under test are destroyed. */
    clobber_vregs(g_clobber);

    /* `fpuclobber`: rewrite the SAVED state so the resumed code legitimately
     * sees different registers. Linux applies whatever the handler leaves in
     * uc_mcontext at sigreturn, so on a correct kernel this flips
     * `preserved` to 0 — the falsification the selftest needs. */
    if (mutant("fpuclobber") && saved != NULL) memcpy(saved, g_clobber, PAT_BYTES);

    g_hit = 1;
}

/* ---------------------------------------------------------------- probe */

void probe_sigfpu(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = fpu_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        out("sigfpu", "simd_preserved", "outcome=setup_failed");
        out("sigfpu", "uc_fpstate", "outcome=setup_failed");
        return;
    }

    fill(g_pattern, 0x3c);
    fill(g_clobber, 0xa5);
    /* `fpunopat`: the registers carry a pattern the handler is not looking
     * for, so the saved state cannot match — falsifies `uc_fpstate` without
     * touching `simd_preserved`, which compares against the read-back. */
    unsigned char loaded[PAT_BYTES];
    memcpy(loaded, g_pattern, PAT_BYTES);
    if (mutant("fpunopat")) fill(loaded, 0x11);

    /* The signal must arrive while the probe spins, so it is armed by a
     * child: `raise()` from this thread would deliver before the asm block
     * is even entered. The guard timer keeps a kernel that never delivers
     * from hanging the run. */
    g_hit = 0;
    g_uc_present = g_uc_live = 0;
    pid_t me = getpid();
    pid_t kicker = fork();
    if (kicker == 0) {
        sleep_ms(SIG_DELAY_MS);
        kill(me, SIGUSR1);
        _exit(0);
    }
    if (kicker < 0) {
        out("sigfpu", "simd_preserved", "outcome=fork_failed");
        out("sigfpu", "uc_fpstate", "outcome=fork_failed");
        return;
    }
    /* A kernel that loses the signal entirely would spin forever. */
    signal(SIGALRM, SIG_DFL);
    alarm(JOBCTL_GUARD_S);

    memset(g_readback, 0, sizeof g_readback);
    load_spin_store(loaded, g_readback, &g_hit);

    alarm(0);
    reap(kicker);

    int preserved = memcmp(g_readback, loaded, PAT_BYTES) == 0;
    int clobber_leaked = memcmp(g_readback, g_clobber, PAT_BYTES) == 0;
    /* `preserved=1` is the whole point: a handler that destroyed the vector
     * registers must not have destroyed the interrupted context's copy.
     * `leaked=1` names the specific failure — the handler's own values still
     * sitting in the resumed thread's registers. */
    out("sigfpu", "simd_preserved", "preserved=%d leaked=%d", preserved, clobber_leaked);
    /* The saved state must EXIST and hold what the interrupted code had; a
     * present-but-stale record would pass a mere non-NULL-pointer check. */
    out("sigfpu", "uc_fpstate", "present=%d live=%d", g_uc_present, g_uc_live);
}
