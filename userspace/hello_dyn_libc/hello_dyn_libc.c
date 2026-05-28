// /bin/hello_dyn_libc — dynamic-linked musl-libc smoke for F230.
// Built per-arch via xtask as a plain dynamic binary (no -static,
// full crt1) — links against libc.so → PT_INTERP=/lib/ld-musl-<arch>.so.1
// and DT_NEEDED=[ld-musl-<arch>.so.1]. The real ld-musl resolves
// printf/getpid/etc and jumps to main. Exit 0 = full pipeline OK:
//   * kernel ELF loader dual-loads exec + PT_INTERP image
//   * ld-musl AUX vector arrives intact, brk works
//   * DT_NEEDED resolution finds the loader is already self-mapped
//   * relocations applied, GOT entries point at musl text
//   * libc constructors run, main() called, stdio flushes
#include <stdio.h>
#include <unistd.h>
int main(void) {
    printf("hello_dyn_libc: pid=%d real-ld-musl OK\n", getpid());
    return 0;
}
