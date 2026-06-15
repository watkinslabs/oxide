/* G19a dynamic-main smoke (docs/59§6): a normal int main() — no custom _start,
 * no -nostartfiles — linked dynamically against the oxide glibc sysroot
 * (crt1 _start → __libc_start_main → main → exit(7)). Proves the dynamic-exe
 * crt path end-to-end through our ld-linux. We declare the libc fns we call. */
long write(int fd, const void *buf, unsigned long n);
int main(void) {
    const char m[] = "g19-dynamic-main-ok\n";
    write(1, m, sizeof(m) - 1);
    return 7;
}
