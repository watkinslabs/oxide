/* rtld TLS smoke (docs/59§5): no-libc PIE with its own initial-exec __thread
 * var. The compiler emits a GOTTPOFF/TPOFF64 reloc the rtld must fill with the
 * tp-relative offset; _start reads the var and exits with its value. */
__attribute__((tls_model("initial-exec")))
static __thread int tvar = 7;
void _start(void) {
    int v = tvar;
    __asm__ volatile("syscall" :: "a"(231 /*exit_group*/), "D"((long)v) :);
    __builtin_unreachable();
}
