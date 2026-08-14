#ifndef OXIDE_LINUX_BLKZONED_H
#define OXIDE_LINUX_BLKZONED_H

#include <linux/types.h>

#define BLK_ZONE_TYPE_CONVENTIONAL 1u
#define BLK_ZONE_TYPE_SEQWRITE_REQ 2u
#define BLK_ZONE_TYPE_SEQWRITE_PREF 3u

#define BLK_ZONE_COND_NOT_WP 0u
#define BLK_ZONE_COND_EMPTY 1u
#define BLK_ZONE_COND_IMP_OPEN 2u
#define BLK_ZONE_COND_EXP_OPEN 3u
#define BLK_ZONE_COND_CLOSED 4u
#define BLK_ZONE_COND_READONLY 13u
#define BLK_ZONE_COND_FULL 14u
#define BLK_ZONE_COND_OFFLINE 15u
#define BLK_ZONE_COND_ACTIVE 255u

struct blk_zone {
    u64 start;
    u64 len;
    u64 wp;
    u8 type;
    u8 cond;
    u8 non_seq;
    u8 reset;
    u8 resv[4];
    u64 capacity;
    u8 reserved[24];
};

_Static_assert(sizeof(struct blk_zone) == 64, "blk_zone ABI size");
_Static_assert(__builtin_offsetof(struct blk_zone, wp) == 16, "blk_zone wp offset");
_Static_assert(__builtin_offsetof(struct blk_zone, capacity) == 32, "blk_zone capacity offset");

#endif
