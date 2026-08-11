#ifndef OXIDE_LINUX_KOBJECT_H
#define OXIDE_LINUX_KOBJECT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/kref.h>

#define OXIDE_KOBJECT_NAME_LEN 64

struct attribute;
struct kset;
struct kobject;
struct kernfs_node;

struct kobj_type {
    void (*release)(struct kobject *kobj);
};

struct kobject {
    const char *name;
    struct list_head entry;
    struct kobject *parent;
    struct kset *kset;
    const struct kobj_type *ktype;
    struct kernfs_node *sd;
    struct kref kref;
    unsigned int state_initialized:1;
    unsigned int state_in_sysfs:1;
    unsigned int state_add_uevent_sent:1;
    unsigned int state_remove_uevent_sent:1;
    unsigned int uevent_suppress:1;
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
