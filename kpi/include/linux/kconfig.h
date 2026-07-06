#ifndef OXIDE_LINUX_KCONFIG_H
#define OXIDE_LINUX_KCONFIG_H

#include <generated/autoconf.h>

#define __ARG_PLACEHOLDER_1 0,
#define __take_second_arg(__ignored, val, ...) val
#define __is_defined(x) ___is_defined(x)
#define ___is_defined(val) ____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk) __take_second_arg(arg1_or_junk 1, 0)
#define IS_BUILTIN(option) __is_defined(option)
#define IS_MODULE(option) 0
#define IS_ENABLED(option) IS_BUILTIN(option)

#endif
