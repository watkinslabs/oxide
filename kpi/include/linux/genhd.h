#ifndef OXIDE_LINUX_GENHD_H
#define OXIDE_LINUX_GENHD_H

#include <linux/blk_types.h>
#include <linux/device.h>

#define DISK_NAME_LEN 32u
#define GENHD_FL_REMOVABLE (1u << 0)
#define GENHD_FL_NO_PART_SCAN (1u << 1)

struct block_device_operations;

struct gendisk {
    int major;
    int first_minor;
    int minors;
    char disk_name[DISK_NAME_LEN];
    const struct block_device_operations *fops;
    struct request_queue *queue;
    void *private_data;
    sector_t capacity;
    u32 flags;
    struct device dev;
    u32 registered;
};

struct gendisk *alloc_disk(int minors);
struct gendisk *alloc_disk_node(int minors, int node_id);
void put_disk(struct gendisk *disk);
void add_disk(struct gendisk *disk);
void del_gendisk(struct gendisk *disk);
void set_capacity(struct gendisk *disk, sector_t sectors);
sector_t get_capacity(const struct gendisk *disk);

#endif
