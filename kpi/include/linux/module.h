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
#define module_param(name, type, perm) static const char __param_##name[] __used __section("__param") = #name ":" #type ":" #perm
#define MODULE_PARM_DESC(name, desc) MODULE_INFO(parm_##name, #name ":" desc)

#endif
