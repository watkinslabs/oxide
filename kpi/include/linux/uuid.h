#ifndef OXIDE_LINUX_UUID_H
#define OXIDE_LINUX_UUID_H

#include <linux/types.h>

#define UUID_SIZE 16

typedef struct { u8 b[UUID_SIZE]; } guid_t;
typedef struct { u8 b[UUID_SIZE]; } uuid_t;

extern const guid_t guid_null;
extern const uuid_t uuid_null;

#endif
