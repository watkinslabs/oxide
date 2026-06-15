/* rtld dlopen smoke (docs/59§5): a PIE (own _start, links libc.so.6 for
 * dlopen/dlsym) that dlopen("libfoo.so")+dlsym("foo")+calls it, exiting with
 * the result (99). Proves dlopen/dlsym + the rtld-in-resolution-scope path. */
extern void *dlopen(const char *file, int mode);
extern void *dlsym(void *handle, const char *name);
static void exit_group(long code) {
    __asm__ volatile("syscall" :: "a"(231L), "D"(code) :);
    __builtin_unreachable();
}
void _start(void) {
    void *h = dlopen("libfoo.so", 2 /*RTLD_NOW*/);
    if (!h) exit_group(70);
    int (*f)(void) = (int (*)(void))dlsym(h, "foo");
    if (!f) exit_group(71);
    exit_group(f());
}
