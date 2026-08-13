#ifndef OXIDE_LINUX_MODULE_H
#define OXIDE_LINUX_MODULE_H

#include <linux/export.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>

struct module {
    const char *name;
    unsigned long state;
    unsigned int refcnt;
};

struct kernel_param;
struct kparam_array;
struct kernel_param_ops {
    unsigned int flags;
    int (*set)(const char *val, const struct kernel_param *kp);
    int (*get)(char *buffer, const struct kernel_param *kp);
    void (*free)(void *arg);
};

struct kernel_param {
    const char *name;
    struct module *mod;
    const struct kernel_param_ops *ops;
    const u16 perm;
    s8 level;
    u8 flags;
    union {
        void *arg;
        const struct kparam_array *arr;
    };
};

struct kparam_array {
    unsigned int max;
    unsigned int elemsize;
    unsigned int *num;
    const struct kernel_param_ops *ops;
    void *elem;
};

#define THIS_MODULE ((struct module *)0)
#define __PASTE(a, b) a##b
#define __PASTE2(a, b) __PASTE(a, b)
#define __UNIQUE_ID(prefix) __PASTE2(__UNIQUE_ID_##prefix##_, __COUNTER__)
#define MODULE_INFO(tag, info) static const char __UNIQUE_ID(tag)[] __used __section(".modinfo") = #tag "=" info
#define MODULE_LICENSE(info) MODULE_INFO(license, info)
#define MODULE_AUTHOR(info) MODULE_INFO(author, info)
#define MODULE_DESCRIPTION(info) MODULE_INFO(description, info)
#define MODULE_VERSION(info) MODULE_INFO(version, info)
#define MODULE_ALIAS(info) MODULE_INFO(alias, info)
#define MODULE_FIRMWARE(info) MODULE_INFO(firmware, info)
#define MODULE_DEVICE_TABLE(type, name) extern const typeof(name) __mod_##type##__##name##_device_table __attribute__((alias(#name)))
#define module_driver(__driver, __register, __unregister) \
    static int __init __driver##_init(void) { return __register(&(__driver)); } \
    static void __exit __driver##_exit(void) { __unregister(&(__driver)); } \
    module_init(__driver##_init); \
    module_exit(__driver##_exit)
#define module_param(name, type, perm) static const char __param_##name[] __used __section("__param") = #name ":" #type ":" #perm
#define MODULE_PARM_DESC(name, desc) MODULE_INFO(parm_##name, #name ":" desc)

int try_module_get(struct module *module);
void module_put(struct module *module);
extern const struct kernel_param_ops param_ops_bool;
extern const struct kernel_param_ops param_ops_byte;
extern const struct kernel_param_ops param_ops_int;
extern const struct kernel_param_ops param_ops_uint;
extern const struct kernel_param_ops param_ops_ulong;
extern const struct kernel_param_ops param_array_ops;
int param_set_bool(const char *val, const struct kernel_param *kp);
int param_get_bool(char *buffer, const struct kernel_param *kp);
int param_set_byte(const char *val, const struct kernel_param *kp);
int param_get_byte(char *buffer, const struct kernel_param *kp);
int param_set_int(const char *val, const struct kernel_param *kp);
int param_get_int(char *buffer, const struct kernel_param *kp);
int param_set_uint(const char *val, const struct kernel_param *kp);
int param_set_uint_minmax(const char *val, const struct kernel_param *kp,
                          unsigned int min, unsigned int max);
int param_get_uint(char *buffer, const struct kernel_param *kp);
int param_set_ulong(const char *val, const struct kernel_param *kp);
int param_get_ulong(char *buffer, const struct kernel_param *kp);

#endif
