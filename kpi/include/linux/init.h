#ifndef OXIDE_LINUX_INIT_H
#define OXIDE_LINUX_INIT_H

#include <linux/compiler_types.h>

#define __init __section(".init.text") __cold
#define __initdata __section(".init.data")
#define __exit __section(".exit.text") __cold
#define __exitdata __section(".exit.data")

#define early_initcall(fn) static int (*__initcall_##fn)(void) __used __section(".initcall0.init") = fn
#define core_initcall(fn) static int (*__initcall_##fn)(void) __used __section(".initcall1.init") = fn
#define module_init(fn) static int (*__initcall_##fn)(void) __used __section(".initcall6.init") = fn
#define module_exit(fn) static void (*__exitcall_##fn)(void) __used __section(".exitcall.exit") = fn

#endif
