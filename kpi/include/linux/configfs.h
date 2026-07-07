#ifndef OXIDE_LINUX_CONFIGFS_H
#define OXIDE_LINUX_CONFIGFS_H

#include <linux/types.h>

struct config_item;
struct config_group;

struct configfs_attribute {
    const char *name;
    umode_t mode;
    ssize_t (*show)(struct config_item *item, char *page);
    ssize_t (*store)(struct config_item *item, const char *page, size_t count);
};

struct configfs_bin_attribute {
    struct configfs_attribute attr;
    void *private;
    size_t size;
    ssize_t (*read)(struct config_item *item, void *private, void *buf, char *page, loff_t off, size_t count);
    ssize_t (*write)(struct config_item *item, void *private, void *buf, const char *page, loff_t off, size_t count);
};

struct config_item_type {
    void (*release)(struct config_item *item);
    struct configfs_attribute **attrs;
    struct config_group **default_groups;
    struct configfs_bin_attribute **bin_attrs;
    int (*allow_link)(struct config_item *src, struct config_item *target);
    int (*drop_link)(struct config_item *src, struct config_item *target);
};

struct config_item {
    const char *name;
    struct config_item_type *type;
    void *private;
};

struct config_group {
    struct config_item item;
};

struct configfs_subsystem {
    struct config_group su_group;
};

#define CONFIGFS_ATTR(_pfx, _name) \
    struct configfs_attribute _pfx##attr_##_name = { \
        .name = #_name, \
        .mode = 0644, \
        .show = _pfx##_name##_show, \
        .store = _pfx##_name##_store, \
    }

void config_item_init(struct config_item *item);
void config_item_init_type_name(struct config_item *item, const char *name, struct config_item_type *type);
void config_group_init(struct config_group *group);
void config_group_init_type_name(struct config_group *group, const char *name, struct config_item_type *type);
int configfs_register_subsystem(struct configfs_subsystem *subsys);
void configfs_unregister_subsystem(struct configfs_subsystem *subsys);
int configfs_register_group(struct config_group *parent, struct config_group *group);
void configfs_unregister_group(struct config_group *group);
struct config_item *config_item_get(struct config_item *item);
void config_item_put(struct config_item *item);
int configfs_create_link(struct config_item *parent, struct config_item *target, const char *name);
void configfs_drop_link(struct config_item *parent, struct config_item *target, const char *name);

#endif
