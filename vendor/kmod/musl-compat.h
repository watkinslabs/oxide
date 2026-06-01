/* musl lacks GNU basename() (non-modifying, in <string.h>); it ships
 * only POSIX basename() in <libgen.h> which modifies its argument.
 * kmod calls bare basename() expecting GNU semantics. Force-included via
 * CFLAGS to supply a non-modifying GNU-style basename on musl. */
#ifndef OXIDE_KMOD_MUSL_COMPAT_H
#define OXIDE_KMOD_MUSL_COMPAT_H
#include <string.h>
static inline char *oxide_gnu_basename(const char *p) {
    char *b = strrchr(p, '/');
    return b ? b + 1 : (char *)p;
}
#define basename(p) oxide_gnu_basename(p)
#endif
