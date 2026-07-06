#ifndef OXIDE_LINUX_KREF_H
#define OXIDE_LINUX_KREF_H

#include <linux/refcount.h>

struct kref { refcount_t refcount; };

void kref_init(struct kref *kref);
void kref_get(struct kref *kref);
int kref_put(struct kref *kref, void (*release)(struct kref *kref));

#endif
