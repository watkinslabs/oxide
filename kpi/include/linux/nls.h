#ifndef OXIDE_LINUX_NLS_H
#define OXIDE_LINUX_NLS_H

#include <linux/types.h>

typedef u16 wchar_t;

enum utf16_endian {
    UTF16_HOST_ENDIAN = 0,
    UTF16_LITTLE_ENDIAN = 1,
    UTF16_BIG_ENDIAN = 2,
};

int utf16s_to_utf8s(const wchar_t *pwcs, int len, enum utf16_endian endian, u8 *s, int maxlen);
int utf8s_to_utf16s(const u8 *s, int len, enum utf16_endian endian, wchar_t *pwcs, int maxlen);

#endif
