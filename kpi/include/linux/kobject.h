#ifndef OXIDE_LINUX_KOBJECT_H
#define OXIDE_LINUX_KOBJECT_H

#include <linux/types.h>

#define OXIDE_KOBJECT_NAME_LEN 64

struct attribute;
struct kset;
struct kobject;

struct kobj_type {
    void (*release)(struct kobject *kobj);
};

struct kobject {
    const char *name;
    struct kobject *parent;
    struct kset *kset;
    const struct kobj_type *ktype;
    void *private;
    unsigned int refcount;
    char name_buf[OXIDE_KOBJECT_NAME_LEN];
};

struct kset {
    struct kobject kobj;
};

enum kobject_action {
    KOBJ_ADD = 0,
    KOBJ_REMOVE = 1,
    KOBJ_CHANGE = 2,
};

void kobject_init(struct kobject *kobj, const struct kobj_type *ktype);
struct kobject *kobject_get(struct kobject *kobj);
void kobject_put(struct kobject *kobj);
const char *kobject_name(const struct kobject *kobj);
int kobject_set_name(struct kobject *kobj, const char *fmt, ...) __printf(2, 3);
int kobject_uevent(struct kobject *kobj, enum kobject_action action);

#endif
