// /bin/hello_dyn — `-pie` (non-static) smoke test for the
// PT_INTERP dual-image load. Compiled `musl-gcc -fPIE -pie
// -nostartfiles -nostdlib`, the linker emits PT_INTERP set to
// /lib/ld-musl-x86_64.so.1; the kernel ELF loader honors that
// and our stub interpreter runs first, traces a "dl: hello"
// line, then jumps here. We then write a marker line + exit(0).
//
// No libc calls — purely inline-asm syscalls — so the binary
// has no DT_NEEDED to resolve and the stub interpreter (which
// doesn't yet do DT_NEEDED) can hand off cleanly.

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

__attribute__((force_align_arg_pointer))
void _start(void) {
    static const char msg[] = "hello-from-dyn\n";
    sc3(SYS_write, 1, (long)msg, sizeof(msg) - 1);
    sc1(SYS_exit, 0);
    __builtin_unreachable();
}
