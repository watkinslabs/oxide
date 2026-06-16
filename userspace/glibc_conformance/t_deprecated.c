/* Deprecated / legacy syscall wrappers: revoke (ENOSYS stub) and the x86-only
 * modify_ldt/iopl/ioperm. Diff error returns vs host glibc. (ustat/uselib are
 * shipped too but host glibc keeps them compat-only / non-linkable, so they
 * can't be differentially tested here — they are thin syscall passthroughs.) */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

extern int revoke(const char *);
#ifdef __x86_64__
extern int modify_ldt(int, void *, unsigned long);
extern int iopl(int);
extern int ioperm(unsigned long, unsigned long, int);
#endif

static void show(const char *n, int r) { printf("%s=%d errno=%d\n", n, r, r < 0 ? errno : 0); }

int main(void) {
    errno = 0; show("revoke", revoke("/dev/null"));
#ifdef __x86_64__
    /* modify_ldt(0=read, buf, 0) reads 0 bytes of the LDT — succeeds with 0. */
    char ldt[64];
    errno = 0; show("modify_ldt", modify_ldt(0, ldt, 0));
    /* iopl/ioperm need CAP_SYS_RAWIO → EPERM as an unprivileged caller. */
    errno = 0; show("iopl", iopl(0));
    errno = 0; show("ioperm", ioperm(0x378, 3, 1));
#endif
    return 0;
}
