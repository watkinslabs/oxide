// /bin/hello_dyn — `-pie` (non-static) smoke test for the
// PT_INTERP dual-image load. Compiled `<arch>-linux-musl-gcc -fPIE -pie
// -nostartfiles -nostdlib`, the linker emits PT_INTERP set to
// /lib/ld-musl-<arch>.so.1; the kernel ELF loader honors that
// and our stub interpreter runs first, traces a "dl: hello"
// line, then jumps here. We then write a marker line + exit(0).
//
// No libc calls — purely inline-asm syscalls — so the binary
// has no DT_NEEDED to resolve and the stub interpreter (which
// doesn't yet do DT_NEEDED) can hand off cleanly.
//
// Arch-portable: x86_64 + aarch64 syscall ABIs both supported via
// #ifdef. Rebuild per-arch via xtask.

#if defined(__x86_64__)
  #define SYS_write 1
  #define SYS_exit  60
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
#elif defined(__aarch64__)
  #define SYS_write 64   // aarch64 generic ABI
  #define SYS_exit  93
static long sc3(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile ("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static long sc1(long n, long a) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    __asm__ volatile ("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}
#else
  #error "unsupported architecture"
#endif

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    static const char msg[] = "hello-from-dyn\n";
    sc3(SYS_write, 1, (long)msg, sizeof(msg) - 1);
    sc1(SYS_exit, 0);
    __builtin_unreachable();
}
