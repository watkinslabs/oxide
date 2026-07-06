#ifndef OXIDE_LINUX_RBTREE_H
#define OXIDE_LINUX_RBTREE_H

#include <linux/kernel.h>

struct rb_node {
    unsigned long __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
};

struct rb_root { struct rb_node *rb_node; };
#define RB_ROOT ((struct rb_root) { NULL })
#define rb_entry(ptr, type, member) container_of(ptr, type, member)

void rb_link_node(struct rb_node *node, struct rb_node *parent, struct rb_node **link);
void rb_insert_color(struct rb_node *node, struct rb_root *root);
void rb_erase(struct rb_node *node, struct rb_root *root);
struct rb_node *rb_first(const struct rb_root *root);
struct rb_node *rb_next(const struct rb_node *node);

#endif
