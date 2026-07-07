#ifndef OXIDE_LINUX_TYPES_H
#define OXIDE_LINUX_TYPES_H

#include <linux/stddef.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
typedef _Bool bool;
#define true 1
#define false 0
#endif

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef unsigned long uintptr_t;
typedef long intptr_t;
typedef unsigned long ulong;
typedef unsigned int uint;
typedef unsigned long gfp_t;
typedef unsigned long dma_addr_t;
typedef unsigned int umode_t;
typedef long ssize_t;
typedef long long loff_t;
typedef unsigned int dev_t;
typedef unsigned short __be16;
typedef unsigned short __sum16;
typedef unsigned int __wsum;
typedef int netdev_tx_t;

struct page;
struct device;
struct module;

#endif
