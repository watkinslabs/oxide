/* rtld DT_NEEDED smoke (docs/59§5): a PIE that links against our libc.so.6 and
 * calls one libc fn (strlen). Own _start (no crt). exit_group(strlen(msg))
 * → exit code = length, proving the JUMP_SLOT to libc.so.6 was resolved. */
extern unsigned long strlen(const char *);
void _start(void) {
    const char *m = "hello-dynamic";          /* 13 chars */
    unsigned long n = strlen(m);
    __asm__ volatile("syscall" :: "a"(231 /*exit_group*/), "D"(n) : );
    __builtin_unreachable();
}
