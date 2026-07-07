#ifndef OXIDE_LINUX_DYNAMIC_DEBUG_H
#define OXIDE_LINUX_DYNAMIC_DEBUG_H

#include <linux/compiler_types.h>

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "oxide_module"
#endif

struct device;

#define CLS_BITS 6
#define _DPRINTK_CLASS_DFLT ((1 << CLS_BITS) - 1)
#define _DPRINTK_FLAGS_NONE 0
#define _DPRINTK_FLAGS_PRINT (1 << 0)

struct _ddebug {
    const char *modname;
    const char *function;
    const char *filename;
    const char *format;
    unsigned int lineno:18;
    unsigned int class_id:CLS_BITS;
    unsigned int flags:8;
} __aligned(8);

void __dynamic_pr_debug(struct _ddebug *descriptor, const char *fmt, ...) __printf(2, 3);
void __dynamic_dev_dbg(struct _ddebug *descriptor, const struct device *dev, const char *fmt, ...) __printf(3, 4);

#define DEFINE_DYNAMIC_DEBUG_METADATA(name, fmt) \
    static struct _ddebug name __used __aligned(8) __section("__dyndbg") = { \
        .modname = KBUILD_MODNAME, \
        .function = __func__, \
        .filename = __FILE__, \
        .format = (fmt), \
        .lineno = __LINE__, \
        .class_id = _DPRINTK_CLASS_DFLT, \
        .flags = _DPRINTK_FLAGS_NONE, \
    }

#define dynamic_pr_debug(fmt, ...) do { \
    DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt); \
    __dynamic_pr_debug(&descriptor, fmt, ##__VA_ARGS__); \
} while (0)

#endif
