// /lib/ld-musl-x86_64.so.1 — minimal dynamic-linker stub (P13-06).
//
// First-pass scope: prove the kernel's PT_INTERP plumbing works end-
// to-end. The kernel loads us at INTERP_LOAD_BIAS (0x4000_0000),
// places auxv on the user stack with AT_BASE=our load base and
// AT_ENTRY=the exec's actual entry, then drops to ring 3 at our
// _start instead of the exec's. We:
//   - walk the auxv to find AT_ENTRY
//   - emit a "dl: hello base=..  entry=.." trace via sys_write
//   - jump to the exec's entry, leaving the stack untouched so its
//     own _start sees the original argc/argv/envp/auxv layout.
//
// What this stub does NOT do (yet — successive PRs):
//   - parse the exec's PT_DYNAMIC for DT_NEEDED
//   - load shared libraries
//   - resolve symbols / apply RELA + JMPREL fixups against the
//     loaded SO graph
//   - run DT_INIT / DT_INIT_ARRAY
//   - TLS init image
//
// As a result this stub only handles binaries whose PT_INTERP we
// honor for the side-effect of a kernel-side dual-image load —
// static-PIE-style binaries that do their own self-relocs and
// expect no dynamic resolution. Real glibc / musl dyn binaries
// will not run until the resolver lands.

#include <stdint.h>

#define SYS_write 1
#define SYS_exit  60

#define AT_NULL  0
#define AT_BASE  7
#define AT_ENTRY 9

static long sc3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile ("syscall"
        : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c)
        : "rcx","r11","memory");
    return r;
}

static long sc1(long n, long a) {
    long r;
    __asm__ volatile ("syscall"
        : "=a"(r) : "0"(n), "D"(a) : "rcx","r11","memory");
    return r;
}

static long mlen(const char* s) { long n=0; while (s[n]) n++; return n; }

// Render `v` as 16 lowercase hex digits into `out`. No prefix.
static void hex16(unsigned long v, char* out) {
    static const char digits[] = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) { out[i] = digits[v & 0xf]; v >>= 4; }
}

static void writes(const char* s) { sc3(SYS_write, 1, (long)s, mlen(s)); }
static void writenl(void) { sc3(SYS_write, 1, (long)"\n", 1); }

// dl_main returns the exec entry-point in rax; the asm trampoline
// restores rsp to argc and jumps there.
long dl_main(long* sp) {
    long argc = sp[0];
    long* p = sp + 1 + argc + 1;          // skip argc + argv[] + NULL
    while (*p) p++;                        // skip envp[]
    p++;                                    // skip envp NULL
    long entry = 0;
    long base  = 0;
    while (*p != AT_NULL) {
        long tag = p[0];
        long val = p[1];
        if (tag == AT_ENTRY) entry = val;
        if (tag == AT_BASE)  base  = val;
        p += 2;
    }

    char buf[17]; buf[16] = 0;
    writes("dl: hello base=0x");
    hex16((unsigned long)base, buf);
    sc3(SYS_write, 1, (long)buf, 16);
    writes(" entry=0x");
    hex16((unsigned long)entry, buf);
    sc3(SYS_write, 1, (long)buf, 16);
    writenl();

    if (!entry) {
        writes("dl: AT_ENTRY missing\n");
        sc1(SYS_exit, 99);
        __builtin_unreachable();
    }

    return entry;
}

// Naked _start: capture original rsp (which the kernel set to
// argc), call into dl_main on a 16-byte-aligned scratch stack,
// then restore rsp to argc and jump to the exec's entry. The
// exec's _start expects the SysV "sp at argc, 0 mod 16" layout
// — which is exactly what the kernel handed us, so we just
// hand it back unchanged.
__attribute__((naked, noreturn))
void _start(void) {
    __asm__ volatile (
        "mov  %%rsp, %%rbx\n\t"     // rbx = original rsp (callee-saved)
        "mov  %%rsp, %%rdi\n\t"     // arg0 = sp
        "and  $-16, %%rsp\n\t"      // align
        "sub  $8,   %%rsp\n\t"      // SysV: rsp-8 mod 16 before call
        "call dl_main\n\t"
        "mov  %%rbx, %%rsp\n\t"     // restore original sp (argc)
        "jmp  *%%rax\n\t"            // jump to exec entry (rax = ret.entry)
        : : : "rbx", "memory"
    );
}
