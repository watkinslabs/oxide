#ifndef OXIDE_LINUX_CRC32_H
#define OXIDE_LINUX_CRC32_H

#include <linux/types.h>
#include <linux/stddef.h>

u32 crc32(u32 seed, const void *data, size_t len);
u32 crc32_le(u32 seed, const u8 *data, size_t len);
u32 crc32_be(u32 seed, const u8 *data, size_t len);
u32 crc32c(u32 seed, const void *data, size_t len);
u32 __crc32c_le(u32 seed, const u8 *data, size_t len);

#endif
