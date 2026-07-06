#ifndef OXIDE_LINUX_GFP_H
#define OXIDE_LINUX_GFP_H

#include <linux/types.h>

#define __GFP_ZERO 0x8000u
#define GFP_KERNEL 0x0000u
#define GFP_ATOMIC 0x0001u
#define GFP_NOWAIT 0x0002u
#define GFP_NOIO 0x0004u
#define GFP_NOFS 0x0008u

#endif
