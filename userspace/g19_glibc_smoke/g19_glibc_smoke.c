/* G19b: a glibc-dynamic binary run on the oxide kernel (docs/59§6). Built
 * against the oxide glibc sysroot (NOT musl) with our Scrt1.o + libc.so.6 +
 * PT_INTERP=/lib/ld-linux-<arch>.so.2. Writes its marker straight to
 * /dev/console so it lands on serial regardless of stdout routing; proves the
 * kernel ELF loader → our ld-linux → libc.so.6 → glibc main path end-to-end.
 * We declare the libc fns we call (we are exercising our own libc). */
long write(int fd, const void *buf, unsigned long n);
int open(const char *path, int flags, ...);
int close(int fd);

int main(void) {
    static const char m[] = "g19-glibc-on-kernel-ok\n";
    int fd = open("/dev/console", 1 /* O_WRONLY */);
    if (fd >= 0) { write(fd, m, sizeof(m) - 1); close(fd); }
    write(1, m, sizeof(m) - 1);
    return 0;
}
