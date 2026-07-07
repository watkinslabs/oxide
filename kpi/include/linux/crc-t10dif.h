#ifndef OXIDE_LINUX_CRC_T10DIF_H
#define OXIDE_LINUX_CRC_T10DIF_H

#include <linux/types.h>
#include <linux/stddef.h>

u16 crc_t10dif_arch(u16 crc, const u8 *data, size_t len);
u16 crc_t10dif_generic(u16 crc, const u8 *data, size_t len);

static inline u16 crc_t10dif_update(u16 crc, const u8 *data, size_t len)
{
    return crc_t10dif_arch(crc, data, len);
}

static inline u16 crc_t10dif(const u8 *data, size_t len)
{
    return crc_t10dif_update(0, data, len);
}

#endif
