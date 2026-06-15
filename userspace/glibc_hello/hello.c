/* G2 smoke for oxide-libc (docs/59§6): exercises the full entry path
 * _start -> __libc_start_main -> main -> write -> return -> exit, linked
 * against our libc.a with -nostdlib. No libc headers (we are the libc);
 * declare the one symbol we call. Built -fno-stack-protector until TLS +
 * AT_RANDOM canary land (G3/G11). */
long write(int fd, const void *buf, unsigned long n);

int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;
    static const char msg[] = "hello from oxide-libc\n";
    write(1, msg, sizeof(msg) - 1);
    return 0;
}
