#ifndef OXIDE_LINUX_KOBJECT_H
#define OXIDE_LINUX_KOBJECT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/spinlock.h>

#define OXIDE_KOBJECT_NAME_LEN 64
#define UEVENT_NUM_ENVP 64
#define UEVENT_BUFFER_SIZE 2048

struct attribute;
struct kset;
struct kobject;
struct kernfs_node;

struct kobj_type {
    void (*release)(struct kobject *kobj);
    const void *sysfs_ops;
    const struct attribute_group **default_groups;
    const void *(*child_ns_type)(const struct kobject *kobj);
    const void *(*namespace)(const struct kobject *kobj);
    void (*get_ownership)(const struct kobject *kobj, void *uid, void *gid);
};

struct kobj_uevent_env {
    char *argv[3];
    char *envp[UEVENT_NUM_ENVP];
    int envp_idx;
    char buf[UEVENT_BUFFER_SIZE];
    int buflen;
};

struct kset_uevent_ops {
    int (*filter)(const struct kobject *kobj);
    const char *(*name)(const struct kobject *kobj);
    int (*uevent)(const struct kobject *kobj, struct kobj_uevent_env *env);
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
    struct list_head list;
    spinlock_t list_lock;
    struct kobject kobj;
    const struct kset_uevent_ops *uevent_ops;
};

enum kobject_action {
    KOBJ_ADD = 0,
    KOBJ_REMOVE = 1,
    KOBJ_CHANGE = 2,
    KOBJ_MOVE = 3,
    KOBJ_ONLINE = 4,
    KOBJ_OFFLINE = 5,
    KOBJ_BIND = 6,
    KOBJ_UNBIND = 7,
};

void kobject_init(struct kobject *kobj, const struct kobj_type *ktype);
struct kobject *kobject_get(struct kobject *kobj);
void kobject_put(struct kobject *kobj);
const char *kobject_name(const struct kobject *kobj);
int kobject_set_name(struct kobject *kobj, const char *fmt, ...) __printf(2, 3);
int kobject_uevent(struct kobject *kobj, enum kobject_action action);
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action, char *envp[]);
int add_uevent_var(struct kobj_uevent_env *env, const char *fmt, ...) __printf(2, 3);

#endif
