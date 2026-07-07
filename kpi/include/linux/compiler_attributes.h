#ifndef OXIDE_LINUX_COMPILER_ATTRIBUTES_H
#define OXIDE_LINUX_COMPILER_ATTRIBUTES_H

#define __always_inline inline __attribute__((__always_inline__))
#define __noinline __attribute__((__noinline__))
#define __noreturn __attribute__((__noreturn__))
#define __packed __attribute__((__packed__))
#define __aligned(x) __attribute__((__aligned__(x)))
#define __section(x) __attribute__((__section__(x)))
#define __used __attribute__((__used__))
#define __maybe_unused __attribute__((__unused__))
#define __printf(a, b) __attribute__((__format__(__printf__, a, b)))
#define __scanf(a, b) __attribute__((__format__(__scanf__, a, b)))
#define __cold __attribute__((__cold__))
#define __visible __attribute__((__externally_visible__))

#endif
