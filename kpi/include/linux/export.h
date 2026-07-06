#ifndef OXIDE_LINUX_EXPORT_H
#define OXIDE_LINUX_EXPORT_H

#include <linux/compiler_types.h>

#define __EXPORT_SYMBOL(sym, sec) \
    extern typeof(sym) sym; \
    static const char __kstrtab_##sym[] __used __section("__ksymtab_strings") = #sym; \
    static const void *__ksymtab_##sym __used __section(sec) = (const void *)&sym

#define EXPORT_SYMBOL(sym) __EXPORT_SYMBOL(sym, "__ksymtab")
#define EXPORT_SYMBOL_GPL(sym) __EXPORT_SYMBOL(sym, "__ksymtab_gpl")

#endif
