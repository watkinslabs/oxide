/* rtld smoke fixture (docs/59§5). A no-libc PIE that makes raw syscalls and
 * uses our ld-linux as PT_INTERP — exercises self-reloc + app RELATIVE reloc
 * + handoff with zero libc dependency. Raw inline asm is intentional here:
 * this is a host-only linker test fixture, not booted userspace. */
static long sys3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}
/* a RELATIVE reloc: a global pointer into our own .rodata (needs the rtld to
 * apply R_X86_64_RELATIVE before _start reads it). */
static const char msg[] = "ld-ok\n";
static const char *const pmsg = msg;
void _start(void) {
    sys3(1, 1, (long)pmsg, 6);   /* write(1, pmsg, 6) — pmsg via RELATIVE */
    sys3(231, 42, 0, 0);          /* exit_group(42) */
    __builtin_unreachable();
}
