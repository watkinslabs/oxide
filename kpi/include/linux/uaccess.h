#ifndef OXIDE_LINUX_UACCESS_H
#define OXIDE_LINUX_UACCESS_H

#include <linux/compiler_types.h>
#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/types.h>

#define VERIFY_READ 0
#define VERIFY_WRITE 1

bool access_ok(const void __user *addr, size_t size);
unsigned long copy_from_user(void *to, const void __user *from, unsigned long n);
unsigned long copy_to_user(void __user *to, const void *from, unsigned long n);
unsigned long clear_user(void __user *to, unsigned long n);

long __get_user_1(const void __user *from, u8 *out);
long __get_user_2(const void __user *from, u16 *out);
long __get_user_4(const void __user *from, u32 *out);
long __get_user_8(const void __user *from, u64 *out);
long __put_user_1(u8 value, void __user *to);
long __put_user_2(u16 value, void __user *to);
long __put_user_4(u32 value, void __user *to);
long __put_user_8(u64 value, void __user *to);

#define get_user(x, ptr) ({ \
    long __gu_err; \
    typeof(*(ptr)) __gu_val = 0; \
    switch (sizeof(*(ptr))) { \
    case sizeof(u8): { u8 __v = 0; __gu_err = __get_user_1((ptr), &__v); __gu_val = (typeof(*(ptr)))__v; break; } \
    case sizeof(u16): { u16 __v = 0; __gu_err = __get_user_2((ptr), &__v); __gu_val = (typeof(*(ptr)))__v; break; } \
    case sizeof(u32): { u32 __v = 0; __gu_err = __get_user_4((ptr), &__v); __gu_val = (typeof(*(ptr)))__v; break; } \
    case sizeof(u64): { u64 __v = 0; __gu_err = __get_user_8((ptr), &__v); __gu_val = (typeof(*(ptr)))__v; break; } \
    default: __gu_err = -EFAULT; break; \
    } \
    (x) = __gu_val; \
    __gu_err; \
})

#define put_user(x, ptr) ({ \
    long __pu_err; \
    typeof(*(ptr)) __pu_val = (x); \
    switch (sizeof(*(ptr))) { \
    case sizeof(u8): __pu_err = __put_user_1((u8)__pu_val, (ptr)); break; \
    case sizeof(u16): __pu_err = __put_user_2((u16)__pu_val, (ptr)); break; \
    case sizeof(u32): __pu_err = __put_user_4((u32)__pu_val, (ptr)); break; \
    case sizeof(u64): __pu_err = __put_user_8((u64)__pu_val, (ptr)); break; \
    default: __pu_err = -EFAULT; break; \
    } \
    __pu_err; \
})

#define __get_user(x, ptr) get_user((x), (ptr))
#define __put_user(x, ptr) put_user((x), (ptr))
#define might_fault() do { } while (0)

#endif
