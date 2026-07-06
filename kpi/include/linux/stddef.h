#ifndef OXIDE_LINUX_STDDEF_H
#define OXIDE_LINUX_STDDEF_H

#define NULL ((void *)0)
typedef __SIZE_TYPE__ size_t;
typedef __PTRDIFF_TYPE__ ptrdiff_t;

#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)

#endif
