#ifndef OXIDE_LINUX_RANDOM_H
#define OXIDE_LINUX_RANDOM_H

#include <linux/types.h>
#include <linux/stddef.h>

void get_random_bytes(void *buf, size_t nbytes);
u32 get_random_u32(void);
u64 get_random_u64(void);
u32 prandom_u32(void);
void add_device_randomness(const void *buf, size_t nbytes);
void add_hwgenerator_randomness(const void *buf, size_t nbytes, size_t entropy);

#endif
