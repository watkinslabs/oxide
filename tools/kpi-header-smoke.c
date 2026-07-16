#include <linux/bitmap.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/atomic.h>
#include <linux/acpi.h>
#include <linux/completion.h>
#include <linux/configfs.h>
#include <linux/crc32.h>
#include <linux/crc32c.h>
#include <linux/crc-t10dif.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/firmware.h>
#include <linux/gfp.h>
#include <linux/hrtimer.h>
#include <linux/idr.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/jiffies.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/nls.h>
#include <linux/of_device.h>
#include <linux/parser.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/phy.h>
#include <linux/pm.h>
#include <linux/pm_runtime.h>
#include <linux/pm_wakeup.h>
#include <linux/random.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/rwlock.h>
#include <linux/rwsem.h>
#include <linux/semaphore.h>
#include <linux/seqlock.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/scsi.h>
#include <linux/spinlock.h>
#include <linux/suspend.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/usb/gadget.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/xdp.h>
#include <crypto/hash.h>

struct sample {
    int value;
    struct list_head link;
    struct rb_node node;
};

static LIST_HEAD(samples);
static DEFINE_XARRAY(sample_xa);
static DEFINE_IDR(sample_idr);
static DECLARE_BITMAP(sample_bits, 128);
static DECLARE_WORK(sample_work, NULL);
static DECLARE_TASKLET(sample_tasklet, NULL, 0);
enum { SAMPLE_MMIO_SIZE = 4096 };
enum { SAMPLE_DMA_SIZE = 4096 };
enum { SAMPLE_DMA_BUF_SIZE = 64 };
enum { SAMPLE_DMA_SG_NENTS = 2 };
enum { SAMPLE_DMA_PAGE_ORDER = 0 };
enum { SAMPLE_DMA_PAGE_OFFSET = 0 };
enum { SAMPLE_IRQ = 1 };
enum { SAMPLE_IO_PORT = 0 };
enum { SAMPLE_ATTR_MODE = 0444 };
enum { SAMPLE_DEVICE_DEVT = 0 };
enum { SAMPLE_PCI_VENDOR = 0x1af4 };
enum { SAMPLE_PCI_DEVICE = 0x1041 };
enum { SAMPLE_PCI_SUBVENDOR = 0x1af4 };
enum { SAMPLE_PCI_SUBDEVICE = 0x0001 };
enum { SAMPLE_PCI_CLASS = 0x020000 };
enum { SAMPLE_PCI_BUS = 0 };
enum { SAMPLE_PCI_SLOT = 1 };
enum { SAMPLE_PCI_FUNC = 0 };
enum { SAMPLE_PCI_BAR = 0 };
enum { SAMPLE_PCI_BAR_START = 0x10000000 };
enum { SAMPLE_PCI_BAR_END = 0x10000fff };
enum { SAMPLE_PCI_CFG_VENDOR_DEVICE = 0 };
enum { SAMPLE_PCI_CFG_COMMAND = 4 };
enum { SAMPLE_PCI_MIN_VECTORS = 1 };
enum { SAMPLE_PCI_MAX_VECTORS = 1 };
enum { SAMPLE_PLATFORM_RESOURCE_COUNT = 2 };
enum { SAMPLE_PLATFORM_MEM_RESOURCE = 0 };
enum { SAMPLE_PLATFORM_IRQ_RESOURCE = 0 };
enum { SAMPLE_CHRDEV_MAJOR = 240 };
enum { SAMPLE_CHRDEV_MINOR = 1 };
enum { SAMPLE_CHRDEV_COUNT = 1 };
enum { SAMPLE_IOCTL_CMD = 0x58434445 };
enum { SAMPLE_WRITEB = 1, SAMPLE_WRITEW = 2, SAMPLE_WRITEL = 3, SAMPLE_WRITEQ = 4 };
enum { SAMPLE_NET_PRIV = 32 };
enum { SAMPLE_SKB_LEN = ETH_HLEN + 20 };
enum { SAMPLE_DISK_MINORS = 1 };
enum { SAMPLE_DISK_SECTORS = 1024 };
enum { SAMPLE_BLOCK_SIZE = SECTOR_SIZE };
enum { SAMPLE_BIO_VECS = 1 };
enum { SAMPLE_BIO_LEN = SECTOR_SIZE };
enum { SAMPLE_BLK_HW_QUEUES = 1 };
enum { SAMPLE_BLK_QUEUE_DEPTH = 64 };
enum { SAMPLE_ABS_MIN = -100 };
enum { SAMPLE_ABS_MAX = 100 };
enum { SAMPLE_ABS_FUZZ = 1 };
enum { SAMPLE_ABS_FLAT = 2 };
enum { SAMPLE_USB_DEVNUM = 1 };
enum { SAMPLE_USB_BULK_LEN = 8 };
enum { SAMPLE_USB_TIMEOUT = 100 };
enum { SAMPLE_PM_AUTOSUSPEND_DELAY = 1 };
enum { SAMPLE_PM_WAKE_MSEC = 1 };
enum { SAMPLE_PM_SCHEDULE_DELAY = 0 };
enum { SAMPLE_RANDOM_LEN = 16 };
enum { SAMPLE_CRYPTO_DIGEST_LEN = 32 };
enum { SAMPLE_USERCOPY_LEN = 8 };
enum { SAMPLE_DEBUG_VALUE_INIT = 7 };
enum { SAMPLE_FIRMWARE_BUF_LEN = 64 };
enum { SAMPLE_SCSI_LUN = 7 };
enum { SAMPLE_SCSI_SENSE_KEY = 5 };
enum { SAMPLE_SCSI_ASC = 0x20 };
enum { SAMPLE_SCSI_ASCQ = 0 };
static const u8 sample_mac[ETH_ALEN] = { 0x02, 0x4f, 0x58, 0x00, 0x00, 0x01 };
static void sample_release(struct kref *kref) { (void)kref; }
static int sample_thread(void *data) { return data != NULL; }
static void sample_timer_fn(struct timer_list *timer) { (void)timer; }
static enum hrtimer_restart sample_hrtimer_fn(struct hrtimer *timer) { (void)timer; return HRTIMER_NORESTART; }
static irqreturn_t sample_irq_handler(int irq, void *dev) { (void)irq; (void)dev; return IRQ_HANDLED; }
static void sample_devres_action(void *data) { (void)data; }
static void sample_firmware_cont(const struct firmware *fw, void *context)
{
    (void)fw; (void)context;
}
static int sample_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    (void)pdev; (void)id; return 0;
}
static void sample_pci_remove(struct pci_dev *pdev) { (void)pdev; }
static int sample_platform_probe(struct platform_device *pdev)
{
    platform_set_drvdata(pdev, pdev);
    return platform_get_drvdata(pdev) == NULL ? -ENODEV : 0;
}
static int sample_platform_remove(struct platform_device *pdev)
{
    platform_set_drvdata(pdev, NULL);
    return 0;
}
static void sample_platform_shutdown(struct platform_device *pdev) { (void)pdev; }
static int sample_pm_suspend(struct device *dev) { (void)dev; return 0; }
static int sample_pm_resume(struct device *dev) { (void)dev; return 0; }
static int sample_pm_idle(struct device *dev) { (void)dev; return 0; }
static int sample_usb_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
    usb_set_intfdata(intf, (void *)id);
    return usb_get_intfdata(intf) == NULL ? -ENODEV : 0;
}
static void sample_usb_disconnect(struct usb_interface *intf) { usb_set_intfdata(intf, NULL); }
static int sample_gadget_bind(struct usb_gadget *gadget, struct usb_gadget_driver *driver)
{
    (void)gadget; (void)driver; return 0;
}
static int sample_gadget_setup(struct usb_gadget *gadget, const struct usb_ctrlrequest *ctrl)
{
    (void)gadget; (void)ctrl; return 0;
}
static void sample_gadget_disconnect(struct usb_gadget *gadget) { (void)gadget; }
static int sample_net_open(struct net_device *dev) { (void)dev; return 0; }
static int sample_net_stop(struct net_device *dev) { (void)dev; return 0; }
static void sample_net_set_rx_mode(struct net_device *dev)
{
    struct netdev_hw_addr *ha;
    netdev_for_each_mc_addr(ha, dev) { (void)ha->addr[0]; }
    netdev_for_each_uc_addr(ha, dev) { (void)ha->addr[0]; }
    (void)netdev_mc_count(dev);
    (void)netdev_uc_count(dev);
}
static int sample_napi_poll(struct napi_struct *napi, int budget)
{
    (void)napi; return budget;
}
static void sample_phy_link_change(struct net_device *dev) { (void)dev; }
static int sample_make_request(struct request_queue *queue, struct bio *bio)
{
    (void)queue;
    bio->bi_status = BLK_STS_OK;
    return bio_op(bio) == REQ_OP_DISCARD ? 0 : (int)bio->bi_size;
}
static blk_status_t sample_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
    (void)hctx;
    blk_mq_start_request(bd->rq);
    blk_mq_end_request(bd->rq, BLK_STS_OK);
    return BLK_STS_OK;
}
static void sample_complete_rq(struct request *rq) { (void)rq; }
static netdev_tx_t sample_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
    (void)dev;
    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}
static int sample_chr_open(struct inode *inode, struct file *file)
{
    file->private_data = inode;
    return 0;
}
static ssize_t sample_chr_read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
    (void)file; (void)buf; (void)ppos;
    return (ssize_t)count;
}
static ssize_t sample_chr_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
    (void)file; (void)buf; (void)ppos;
    return (ssize_t)count;
}
static long sample_chr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    (void)file; (void)cmd; (void)arg;
    return 0;
}
static int sample_chr_release(struct inode *inode, struct file *file)
{
    (void)inode; (void)file;
    return 0;
}
static const struct file_operations sample_fops = {
    .owner = THIS_MODULE,
    .open = sample_chr_open,
    .read = sample_chr_read,
    .write = sample_chr_write,
    .unlocked_ioctl = sample_chr_ioctl,
    .release = sample_chr_release,
    .llseek = noop_llseek,
};
static int sample_seq_show(struct seq_file *m, void *v)
{
    (void)v;
    seq_puts(m, "sample ");
    seq_putc(m, 'x');
    seq_write(m, ":", 1);
    return seq_printf(m, "%u\n", 1);
}
static int sample_seq_open(struct inode *inode, struct file *file)
{
    (void)inode;
    return single_open(file, sample_seq_show, NULL);
}
static struct vfsmount *sample_debugfs_automount(struct dentry *dentry, void *data)
{
    (void)dentry; (void)data; return NULL;
}
static const struct file_operations sample_seq_fops = {
    .owner = THIS_MODULE,
    .open = sample_seq_open,
    .read = seq_read,
    .release = single_release,
    .llseek = seq_lseek,
};
static const struct pci_device_id sample_pci_ids[] = {
    { PCI_DEVICE(SAMPLE_PCI_VENDOR, SAMPLE_PCI_DEVICE) },
    { 0, 0, 0, 0, 0, 0, 0 },
};
static const struct usb_device_id sample_usb_ids[] = {
    { USB_DEVICE(SAMPLE_PCI_VENDOR, SAMPLE_PCI_DEVICE) },
    { USB_INTERFACE_INFO(USB_CLASS_HID, 0, 0) },
    { 0 }
};
static const struct platform_device_id sample_platform_ids[] = {
    { "sample-platform", SAMPLE_PCI_DEVICE },
    { "", 0 },
};
static const struct of_device_id sample_of_ids[] = {
    { .compatible = "oxide,sample-platform", .data = &sample_of_ids },
    { NULL, NULL, NULL, NULL },
};
static const struct acpi_device_id sample_acpi_ids[] = {
    { "OXID0001", SAMPLE_PCI_DEVICE },
    { "", 0 },
};
static const struct net_device_ops sample_netdev_ops = {
    .ndo_open = sample_net_open,
    .ndo_stop = sample_net_stop,
    .ndo_start_xmit = sample_net_xmit,
    .ndo_set_rx_mode = sample_net_set_rx_mode,
};
static const struct block_device_operations sample_blk_ops = {
    .owner = THIS_MODULE,
};
static const struct blk_mq_ops sample_mq_ops = {
    .queue_rq = sample_queue_rq,
    .complete = sample_complete_rq,
};
static const struct dev_pm_ops sample_pm_ops = {
    SET_SYSTEM_SLEEP_PM_OPS(sample_pm_suspend, sample_pm_resume),
    SET_RUNTIME_PM_OPS(sample_pm_suspend, sample_pm_resume, sample_pm_idle),
};
static ssize_t sample_attr_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    (void)dev; (void)attr; (void)buf; return 0;
}
static DEVICE_ATTR(sample, SAMPLE_ATTR_MODE, sample_attr_show, NULL);
static ssize_t sample_config_show(struct config_item *item, char *page)
{
    (void)item; (void)page; return 0;
}
static ssize_t sample_config_store(struct config_item *item, const char *page, size_t count)
{
    (void)item; (void)page; return (ssize_t)count;
}

static int sample_simple_get(void *data, u64 *value)
{
    (void)data;
    *value = 7;
    return 0;
}

static int sample_simple_set(void *data, u64 value)
{
    (void)data; (void)value;
    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(sample_simple_fops, sample_simple_get, sample_simple_set, "%llu\n");

static ssize_t sample_config_bin_read(struct config_item *item, void *private, void *buf, char *page, loff_t off, size_t count)
{
    (void)item; (void)private; (void)buf; (void)page; (void)off; return (ssize_t)count;
}

static ssize_t sample_config_bin_write(struct config_item *item, void *private, void *buf, const char *page, loff_t off, size_t count)
{
    (void)item; (void)private; (void)buf; (void)page; (void)off; return (ssize_t)count;
}

static int sample_config_allow_link(struct config_item *src, struct config_item *target)
{
    (void)src; (void)target; return 0;
}

static int sample_config_drop_link(struct config_item *src, struct config_item *target)
{
    (void)src; (void)target; return 0;
}

static struct config_item *sample_config_make_item(struct config_group *group, const char *name)
{
    (void)group; (void)name; return NULL;
}

static struct config_group *sample_config_make_group(struct config_group *group, const char *name)
{
    (void)group; (void)name; return NULL;
}

static void sample_config_drop_item(struct config_group *group, struct config_item *item)
{
    (void)group; (void)item;
}

static struct configfs_attribute sample_config_attr = {
    .name = "sample",
    .mode = 0644,
    .show = sample_config_show,
    .store = sample_config_store,
};
static struct configfs_attribute *sample_config_attrs[] = {
    &sample_config_attr,
    NULL,
};
static struct configfs_bin_attribute sample_config_bin_attr = {
    .attr = {
        .name = "blob",
        .mode = 0600,
    },
    .private = NULL,
    .size = 4,
    .read = sample_config_bin_read,
    .write = sample_config_bin_write,
};
static struct configfs_bin_attribute *sample_config_bin_attrs[] = {
    &sample_config_bin_attr,
    NULL,
};
static struct config_group sample_config_child;
static struct config_group *sample_config_default_groups[] = {
    &sample_config_child,
    NULL,
};
static struct config_item_type sample_config_child_type = {
    .release = NULL,
    .attrs = sample_config_attrs,
    .bin_attrs = sample_config_bin_attrs,
};
static struct config_item_type sample_config_type = {
    .release = NULL,
    .attrs = sample_config_attrs,
    .default_groups = sample_config_default_groups,
    .bin_attrs = sample_config_bin_attrs,
    .allow_link = sample_config_allow_link,
    .drop_link = sample_config_drop_link,
    .make_item = sample_config_make_item,
    .make_group = sample_config_make_group,
    .drop_item = sample_config_drop_item,
};

static int __init sample_init(void)
{
    struct sample s;
    spinlock_t spl;
    raw_spinlock_t raw;
    struct mutex m;
    rwlock_t rwl;
    struct rw_semaphore sem;
    struct semaphore semaphore;
    seqlock_t seq;
    struct completion comp;
    wait_queue_head_t wait;
    wait_queue_entry_t wait_entry;
    swait_queue_head_t swait;
    struct timer_list timer;
    struct hrtimer hrtimer;
    struct delayed_work delayed;
    struct workqueue_struct *wq;
    struct task_struct *task;
    struct timespec64 ts64;
    struct scatterlist sg[SAMPLE_DMA_SG_NENTS];
    struct sg_table sg_table;
    struct sg_mapping_iter sg_iter;
    struct scatterlist *sg_allocated;
    unsigned int sg_allocated_nents;
    struct device dev;
    struct kobject kobj;
    struct kobj_type ktype = { NULL };
    struct attribute sample_sysfs_attr = { "sample", 0444 };
    struct class *class;
    struct bus_type bus = { "sample-bus", NULL };
    struct device_driver driver = {
        .name = "sample-driver",
        .bus = &bus,
        .owner = THIS_MODULE,
    };
    struct device *root_dev;
    struct device *created_dev;
    struct dentry *debug_dir;
    struct dentry *debug_file;
    struct dentry *debug_blob_file;
    struct dentry *debug_link;
    struct debugfs_blob_wrapper debug_blob;
    u32 debug_value = SAMPLE_DEBUG_VALUE_INIT;
    char debug_blob_data[4] = { 'd', 'a', 't', 'a' };
    u8 firmware_buf[SAMPLE_FIRMWARE_BUF_LEN];
    u32 debug_regs[2] = { 0x12345678, 0x90abcdef };
    const struct debugfs_reg32 debug_reg_defs[] = {
        { "status", 0 },
        { "control", 4 },
    };
    struct debugfs_regset32 debug_regset = {
        .regs = debug_reg_defs,
        .nregs = 2,
        .base = debug_regs,
    };
    struct configfs_subsystem subsys;
    struct cdev cdev;
    struct miscdevice misc = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "sample-misc",
        .fops = &sample_fops,
        .mode = 0600,
    };
    struct pci_dev pdev;
    struct platform_device platdev;
    struct resource plat_resources[SAMPLE_PLATFORM_RESOURCE_COUNT];
    struct device_node of_node;
    struct acpi_device acpi_dev;
    const struct firmware *fw;
    struct net_device *netdev;
    struct sk_buff *skb;
    unsigned char *skb_data;
    struct napi_struct napi;
    struct phy_device phydev;
    struct ethtool_ts_info tsinfo;
    struct ethtool_eee eee;
    unsigned long link_modes[1] = { 0 };
    u32 legacy_modes = 0;
    u8 ethtool_buf[ETH_GSTRING_LEN * 2];
    u8 *ethtool_ptr = ethtool_buf;
    char skb_copy[SAMPLE_SKB_LEN];
    struct request_queue *queue;
    struct request_queue *mq_queue;
    struct gendisk *disk;
    struct gendisk *mq_disk;
    struct bio *bio;
    struct request *rq;
    struct block_device bdev;
    struct queue_limits limits = {
        SAMPLE_BLOCK_SIZE, SAMPLE_BLOCK_SIZE, SAMPLE_BLOCK_SIZE, 0,
        SAMPLE_DISK_SECTORS, SAMPLE_BIO_VECS, 0, 0
    };
    struct blk_mq_tag_set tag_set = {
        &sample_mq_ops, SAMPLE_BLK_HW_QUEUES, SAMPLE_BLK_QUEUE_DEPTH,
        0, 0, 0, &s
    };
    struct input_dev *input;
    struct input_event input_ev;
    struct usb_device udev;
    struct usb_interface uintf;
    struct usb_host_interface ualt;
    struct usb_endpoint_descriptor uep;
    struct usb_ep gadget_ep;
    struct usb_request *gadget_req;
    struct usb_gadget gadget;
    struct usb_gadget_driver gadget_driver = {
        .function = "sample-gadget",
        .max_speed = USB_SPEED_HIGH,
        .bind = sample_gadget_bind,
        .setup = sample_gadget_setup,
        .disconnect = sample_gadget_disconnect,
    };
    struct scsi_lun scsi_lun;
    u8 scsi_cdb[16] = { 0 };
    u8 scsi_sense[SCSI_SENSE_BUFFERSIZE];
    struct usb_driver udrv = {
        .name = "sample-usb",
        .probe = sample_usb_probe,
        .disconnect = sample_usb_disconnect,
        .id_table = sample_usb_ids,
    };
    struct urb *urb;
    struct pci_driver pdrv = {
        .name = "sample-pci",
        .id_table = sample_pci_ids,
        .probe = sample_pci_probe,
        .remove = sample_pci_remove,
        .driver = {
            .name = "sample-pci",
            .owner = THIS_MODULE,
        },
    };
    struct platform_driver pldrv = {
        .probe = sample_platform_probe,
        .remove = sample_platform_remove,
        .shutdown = sample_platform_shutdown,
        .driver = {
            .name = "sample-platform",
            .owner = THIS_MODULE,
            .of_match_table = sample_of_ids,
            .acpi_match_table = sample_acpi_ids,
            .pm = &sample_pm_ops,
        },
        .id_table = sample_platform_ids,
    };
    struct page *page;
    struct resource *plat_res;
    dma_addr_t dma;
    dev_t chrdev_devt;
    int chrdev_major;
    u64 dma_mask;
    void *coherent;
    char dma_buf[SAMPLE_DMA_BUF_SIZE];
    atomic_t atom;
    refcount_t refs;
    struct kref kref;
    struct module owner;
    char param_buf[64];
    bool param_bool = false;
    int param_int = 0;
    unsigned int param_uint = 0;
    unsigned long param_ulong = 0;
    unsigned int param_arr_vals[3] = { 0 };
    unsigned int param_arr_num = 0;
    struct kparam_array param_arr = {
        .max = 3,
        .elemsize = sizeof(param_arr_vals[0]),
        .num = &param_arr_num,
        .ops = &param_ops_uint,
        .elem = param_arr_vals,
    };
    struct kernel_param param_bool_kp = { .name = "param_bool", .mod = &owner, .ops = &param_ops_bool, .arg = &param_bool };
    struct kernel_param param_int_kp = { .name = "param_int", .mod = &owner, .ops = &param_ops_int, .arg = &param_int };
    struct kernel_param param_uint_kp = { .name = "param_uint", .mod = &owner, .ops = &param_ops_uint, .arg = &param_uint };
    struct kernel_param param_ulong_kp = { .name = "param_ulong", .mod = &owner, .ops = &param_ops_ulong, .arg = &param_ulong };
    struct kernel_param param_arr_kp = { .name = "param_arr", .mod = &owner, .ops = &param_array_ops, .arr = &param_arr };
    struct lock_class_key key;
    unsigned int start;
    void __iomem *regs;
    const void *match_data;
    u8 port8;
    u8 pci_cfg8;
    u16 pci_cfg16;
    u32 pci_cfg32;
    u32 crc;
    u16 crc16;
    u8 random_buf[SAMPLE_RANDOM_LEN];
    u8 digest[SAMPLE_CRYPTO_DIGEST_LEN];
    struct kmem_cache_args cache_args = {
        .align = sizeof(void *),
        .ctor = NULL,
    };
    struct kmem_cache *cache;
    void *cache_obj;
    u8 usercopy_src[SAMPLE_USERCOPY_LEN];
    u8 usercopy_dst[SAMPLE_USERCOPY_LEN];
    u32 user_value;
    u32 __user *user_value_ptr;
    struct crypto_shash *shash;
    struct shash_desc shash_desc;
    int usb_actual;
    char usb_buf[SAMPLE_USB_BULK_LEN];
    char str_buf[32];
    char str_copy[32];
    char *str_cursor;
    char *str_token;
    u8 mac_buf[ETH_ALEN];
    unsigned char hex_bin[2];
    char hex_out[4];
    int parsed_int;
    u16 parsed_u16;
    bool parsed_bool;
    INIT_LIST_HEAD(&s.link);
    list_add(&s.link, &samples);
    set_bit(3, sample_bits);
    pr_info("sample %d\n", test_bit(3, sample_bits));
    (void)container_of(&s.link, struct sample, link);
    (void)kmalloc(16, GFP_KERNEL);
    (void)__kmalloc_noprof(16, GFP_KERNEL);
    (void)__kmalloc_cache_noprof(NULL, GFP_KERNEL, 16);
    (void)__kvmalloc_node_noprof(16, GFP_KERNEL, -1);
    cache = __kmem_cache_create_args("sample-cache", 32, &cache_args, 0);
    cache_obj = kmem_cache_alloc_noprof(cache, GFP_KERNEL | __GFP_ZERO);
    kmem_cache_free(cache, cache_obj);
    kmem_cache_destroy(cache);
    (void)kzalloc(16, GFP_KERNEL);
    (void)kcalloc(2, 8, GFP_KERNEL);
    kfree(NULL);
    kvfree(NULL);
    kvfree_call_rcu(NULL, NULL);
    (void)vmalloc(SAMPLE_MMIO_SIZE);
    (void)vzalloc_noprof(SAMPLE_MMIO_SIZE);
    vfree(NULL);
    page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
    (void)vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    vunmap(NULL);
    (void)page;
    (void)alloc_pages_noprof(GFP_KERNEL, 0);
    (void)__alloc_pages_noprof(GFP_KERNEL, 0, -1, NULL);
    (void)__get_free_pages(GFP_KERNEL, 0);
    free_pages(0, 0);
    (void)page_address(NULL);
    (void)page_to_phys(NULL);
    (void)kstrdup("driver", GFP_KERNEL);
    (void)kstrndup("driver", 3, GFP_KERNEL);
    (void)kmemdup_noprof("driver", 6, GFP_KERNEL);
    (void)kasprintf(GFP_KERNEL, "driver %d", 1);
    (void)memset(str_buf, 0, sizeof(str_buf));
    (void)memcpy(str_copy, str_buf, sizeof(str_buf));
    (void)memcmp(str_copy, str_buf, sizeof(str_buf));
    (void)memcpy_and_pad(str_copy, sizeof(str_copy), "x", 1, 0);
    (void)strcpy(str_buf, " yes ");
    (void)strncpy(str_copy, str_buf, sizeof(str_copy));
    (void)strlen(str_buf);
    (void)strnlen(str_buf, sizeof(str_buf));
    (void)strcmp(str_buf, " yes ");
    (void)strncmp(str_buf, " yes ", 5);
    (void)strncasecmp(str_buf, " YES ", 5);
    (void)strchr(str_buf, 'y');
    (void)strstr(str_buf, "yes");
    (void)strim(str_buf);
    (void)sized_strscpy(str_buf, "copy", sizeof(str_buf));
    str_cursor = str_buf;
    str_token = strsep(&str_cursor, ",");
    (void)str_token;
    (void)hex2bin(hex_bin, "0aff", sizeof(hex_bin));
    (void)bin2hex(hex_out, hex_bin, sizeof(hex_bin));
    (void)hex_to_bin('f');
    (void)simple_strtoul("42", NULL, 10);
    (void)sscanf("42 ok", "%d %s", &parsed_int, str_buf);
    (void)kstrtoint("-7", 10, &parsed_int);
    (void)kstrtou16("65535", 10, &parsed_u16);
    (void)kstrtobool("on", &parsed_bool);
    (void)snprintf(str_buf, sizeof(str_buf), "v=%d", parsed_int);
    (void)scnprintf(str_buf, sizeof(str_buf), "v=%u", parsed_u16);
    (void)sprintf(str_buf, "%s", "ok");
    pr_debug("parsed=%d\n", parsed_int);
    print_hex_dump("7", "sample", 0, 16, 1, random_buf, sizeof(random_buf), true);
    {
        static const struct match_token toks[] = {
            { 7, "mode=%s" },
            { 0, NULL },
        };
        substring_t args[1];
        (void)match_token("mode=fast", toks, args);
        (void)match_strdup(&args[0]);
        (void)match_int(&args[0], &parsed_int);
    }
    (void)_find_first_bit(sample_bits, 128);
    (void)_find_next_bit(sample_bits, 128, 1);
    {
        wchar_t wide[8];
        u8 narrow[16];
        (void)utf8s_to_utf16s((const u8 *)"ok", 2, UTF16_HOST_ENDIAN, wide, 8);
        (void)utf16s_to_utf8s(wide, 2, UTF16_HOST_ENDIAN, narrow, 16);
    }
    {
        DEFINE_DYNAMIC_DEBUG_METADATA(devdbg_descriptor, "dev=%s\n");
        __dynamic_dev_dbg(&devdbg_descriptor, &dev, "dev=%s\n", "sample");
    }
    (void)sysfs_emit(str_buf, "v=%d\n", parsed_int);
    (void)sysfs_emit_at(str_buf, 2, "u=%u\n", parsed_u16);
    (void)request_irq(SAMPLE_IRQ, sample_irq_handler, IRQF_SHARED, "sample", &s);
    disable_irq_nosync(SAMPLE_IRQ);
    enable_irq(SAMPLE_IRQ);
    synchronize_irq(SAMPLE_IRQ);
    (void)irq_set_affinity_hint(SAMPLE_IRQ, NULL);
    (void)irq_update_affinity_hint(SAMPLE_IRQ, NULL);
    (void)in_irq();
    (void)in_interrupt();
    free_irq(SAMPLE_IRQ, &s);
    get_random_bytes(random_buf, sizeof(random_buf));
    add_device_randomness(random_buf, sizeof(random_buf));
    add_hwgenerator_randomness(random_buf, sizeof(random_buf), sizeof(random_buf));
    crc = crc32(0, random_buf, sizeof(random_buf));
    crc = crc32_le(crc, random_buf, sizeof(random_buf));
    crc = crc32_be(crc, random_buf, sizeof(random_buf));
    crc = crc32c(crc, random_buf, sizeof(random_buf));
    crc = __crc32c_le(crc, random_buf, sizeof(random_buf));
    crc16 = crc_t10dif_arch(0, random_buf, sizeof(random_buf));
    crc16 = crc_t10dif_generic(crc16, random_buf, sizeof(random_buf));
    crc16 = crc_t10dif_update(crc16, random_buf, sizeof(random_buf));
    crc16 = crc_t10dif(random_buf, sizeof(random_buf));
    (void)crc16;
    crc ^= get_random_u32();
    crc ^= prandom_u32();
    crc ^= (u32)get_random_u64();
    shash = crypto_alloc_shash("sha256", CRYPTO_ALG_TYPE_SHASH, 0);
    if (shash != NULL) {
        shash_desc.tfm = shash;
        shash_desc.flags = 0;
        (void)crypto_shash_digestsize(shash);
        (void)crypto_shash_descsize(shash);
        (void)crypto_shash_digest(&shash_desc, random_buf, sizeof(random_buf), digest);
        crypto_free_shash(shash);
    }
    (void)crc;
    (void)request_threaded_irq(SAMPLE_IRQ, sample_irq_handler, sample_irq_handler, IRQF_ONESHOT, "sample", &s);
    (void)access_ok(usercopy_dst, sizeof(usercopy_dst));
    (void)copy_from_user(usercopy_dst, usercopy_src, sizeof(usercopy_dst));
    (void)copy_to_user(usercopy_dst, usercopy_src, sizeof(usercopy_src));
    (void)clear_user(usercopy_dst, sizeof(usercopy_dst));
    user_value_ptr = (u32 __user *)usercopy_dst;
    (void)get_user(user_value, user_value_ptr);
    (void)put_user(user_value, user_value_ptr);
    might_fault();
    dma_mask = DMA_BIT_MASK(DMA_ULL_BITS);
    dev.dma_mask = &dma_mask;
    dev.coherent_dma_mask = DMA_BIT_MASK(DMA_ULL_BITS);
    dev.driver_data = NULL;
    dev.parent = NULL;
    dev.bus = &bus;
    dev.class = NULL;
    dev.driver = &driver;
    dev.init_name = "sample-dev";
    dev.release = NULL;
    dev.power.runtime_status = RPM_ACTIVE;
    device_initialize(&dev);
    (void)dev_set_name(&dev, "sample%d", 1);
    (void)device_add(&dev);
    pm_runtime_enable(&dev);
    pm_runtime_set_suspended(&dev);
    (void)pm_runtime_get_sync(&dev);
    pm_runtime_mark_last_busy(&dev);
    pm_runtime_set_autosuspend_delay(&dev, SAMPLE_PM_AUTOSUSPEND_DELAY);
    pm_runtime_use_autosuspend(&dev);
    (void)pm_runtime_autosuspend_expiration(&dev);
    (void)pm_runtime_put_sync(&dev);
    pm_runtime_dont_use_autosuspend(&dev);
    (void)pm_schedule_suspend(&dev, SAMPLE_PM_SCHEDULE_DELAY);
    (void)pm_runtime_suspended(&dev);
    (void)device_init_wakeup(&dev, true);
    (void)device_may_wakeup(&dev);
    pm_wakeup_event(&dev, SAMPLE_PM_WAKE_MSEC);
    pm_stay_awake(&dev);
    pm_relax(&dev);
    (void)dev_pm_suspend(&dev);
    (void)dev_pm_resume(&dev);
    (void)PM_SUSPEND_MEM;
    dev_set_drvdata(&dev, &s);
    (void)dev_get_drvdata(&dev);
    (void)dev_name(&dev);
    (void)device_create_file(&dev, &dev_attr_sample);
    device_remove_file(&dev, &dev_attr_sample);
    kobject_init(&kobj, &ktype);
    (void)kobject_set_name(&kobj, "sample-kobj%d", 1);
    (void)kobject_name(&kobj);
    (void)kobject_get(&kobj);
    (void)sysfs_create_file(&kobj, &sample_sysfs_attr);
    sysfs_remove_file(&kobj, &sample_sysfs_attr);
    (void)kobject_uevent(&kobj, KOBJ_CHANGE);
    kobject_put(&kobj);
    kobject_put(&kobj);
    (void)devm_kmalloc(&dev, 16, GFP_KERNEL);
    (void)devm_kzalloc(&dev, 16, GFP_KERNEL);
    devm_kfree(&dev, NULL);
    (void)devm_add_action_or_reset(&dev, sample_devres_action, &s);
    devm_remove_action(&dev, sample_devres_action, &s);
    dev_info(&dev, "sample device %s\n", dev_name(&dev));
    device_del(&dev);
    (void)bus_register(&bus);
    (void)driver_register(&driver);
    driver_unregister(&driver);
    bus_unregister(&bus);
    class = class_create(THIS_MODULE, "sample-class");
    created_dev = device_create(class, NULL, SAMPLE_DEVICE_DEVT, &s, "sample-created%d", 1);
    device_destroy(class, SAMPLE_DEVICE_DEVT);
    device_unregister(created_dev);
    class_destroy(class);
    root_dev = root_device_register("sample-root");
    root_device_unregister(root_dev);
    debug_dir = debugfs_create_dir("sample", NULL);
    debug_file = debugfs_create_u32("value", 0600, debug_dir, &debug_value);
    debugfs_remove(debug_file);
    debug_file = debugfs_create_file_size("simple", 0600, debug_dir, &debug_value, &sample_simple_fops, 8);
    debugfs_remove(debugfs_create_file("seq", 0400, debug_dir, NULL, &sample_seq_fops));
    debugfs_remove(debugfs_create_automount("auto", debug_dir, sample_debugfs_automount, &debug_value));
    debug_blob.data = debug_blob_data;
    debug_blob.size = sizeof(debug_blob_data);
    debug_blob_file = debugfs_create_blob("blob", 0400, debug_dir, &debug_blob);
    debugfs_create_regset32("regs", 0400, debug_dir, &debug_regset);
    debugfs_print_regs32(NULL, debug_reg_defs, 2, debug_regs, "sample_");
    debug_link = debugfs_create_symlink("link", debug_dir, "value");
    debugfs_remove(debug_link);
    debugfs_remove(debug_blob_file);
    debugfs_remove(debug_file);
    debugfs_remove_recursive(debug_dir);
    config_group_init_type_name(&sample_config_child, "child", &sample_config_child_type);
    (void)config_item_set_name(&sample_config_child.item, "child%d", 1);
    config_group_init_type_name(&subsys.su_group, "sample", &sample_config_type);
    (void)configfs_register_subsystem(&subsys);
    (void)configfs_create_link(&subsys.su_group.item, &sample_config_child.item, "child_link");
    configfs_drop_link(&subsys.su_group.item, &sample_config_child.item, "child_link");
    (void)config_item_get(&subsys.su_group.item);
    config_item_put(&subsys.su_group.item);
    (void)config_item_get_unless_zero(&subsys.su_group.item);
    (void)configfs_depend_item(&subsys, &sample_config_child.item);
    configfs_undepend_item(&subsys, &sample_config_child.item);
    configfs_remove_default_groups(&subsys.su_group);
    configfs_unregister_subsystem(&subsys);
    (void)request_firmware(&fw, "sample/fw.bin", &dev);
    (void)request_firmware_direct(&fw, "sample/fw.bin", &dev);
    (void)firmware_request(&fw, "sample/fw.bin", &dev);
    (void)firmware_request_nowarn(&fw, "sample/fw.bin", &dev);
    (void)firmware_request_platform(&fw, "sample/fw.bin", &dev);
    (void)firmware_request_cache(&dev, "sample/fw.bin");
    (void)request_firmware_into_buf(&fw, "sample/fw.bin", &dev, firmware_buf, sizeof(firmware_buf));
    (void)request_partial_firmware_into_buf(&fw, "sample/fw.bin", &dev, firmware_buf,
                                            sizeof(firmware_buf), 0);
    (void)request_firmware_nowait(THIS_MODULE, FW_ACTION_UEVENT, "sample/fw.bin", &dev,
                                  GFP_KERNEL, &s, sample_firmware_cont);
    (void)firmware_request_nowait_nowarn(THIS_MODULE, "sample/fw.bin", &dev,
                                         GFP_KERNEL, &s, sample_firmware_cont);
    if (fw != NULL) {
        (void)fw->size;
        (void)fw->data;
        (void)fw->pages;
        (void)fw->priv;
        release_firmware(fw);
    }
    netdev = alloc_etherdev(SAMPLE_NET_PRIV);
    if (netdev != NULL) {
        netdev->netdev_ops = &sample_netdev_ops;
        netdev->mtu = ETH_DATA_LEN;
        eth_hw_addr_set(netdev, sample_mac);
        netif_stop_queue(netdev);
        netif_start_queue(netdev);
        netif_wake_queue(netdev);
        netif_tx_lock(netdev);
        netif_tx_unlock(netdev);
        netif_tx_stop_all_queues(netdev);
        netif_tx_wake_queue(netdev);
        netif_carrier_off(netdev);
        netif_carrier_on(netdev);
        (void)netif_set_real_num_tx_queues(netdev, 1);
        (void)netif_set_real_num_rx_queues(netdev, 1);
        netif_set_tso_max_size(netdev, 65536);
        netif_set_tso_max_segs(netdev, 64);
        (void)__netif_set_xps_queue(netdev, NULL, 0);
        (void)netif_enable_cpu_rmap(netdev, 1);
        netif_napi_add_weight_locked(netdev, &napi, sample_napi_poll, NAPI_POLL_WEIGHT);
        napi_enable(&napi);
        __napi_schedule(&napi);
        __napi_schedule_irqoff(&napi);
        napi_disable(&napi);
        netif_queue_set_napi(netdev, 0, &napi);
        __netif_napi_del_locked(&napi);
        (void)ethtool_op_get_link(netdev);
        (void)ethtool_op_get_ts_info(netdev, &tsinfo);
        ethtool_convert_legacy_u32_to_link_mode(link_modes, legacy_modes);
        (void)ethtool_convert_link_mode_to_legacy_u32(&legacy_modes, link_modes);
        ethtool_puts(&ethtool_ptr, "rx");
        ethtool_sprintf(&ethtool_ptr, "tx");
        net_dim_work_cancel(NULL);
        (void)eth_validate_addr(netdev);
        (void)eth_platform_get_mac_address(&dev, mac_buf);
        (void)phy_connect_direct(netdev, &phydev, sample_phy_link_change, 0);
        phy_start(&phydev);
        phy_stop(&phydev);
        (void)phy_resume(&phydev);
        (void)phy_suspend(&phydev);
        (void)phy_start_aneg(&phydev);
        (void)phy_init_hw(&phydev);
        (void)genphy_soft_reset(&phydev);
        phy_get_pause(&phydev, NULL, NULL);
        phy_set_asym_pause(&phydev, true, false);
        phy_support_asym_pause(&phydev);
        (void)phy_support_eee(&phydev);
        (void)phy_ethtool_get_eee(&phydev, &eee);
        (void)phy_ethtool_set_eee(&phydev, &eee);
        (void)phy_ethtool_nway_reset(&phydev);
        (void)phy_set_max_speed(&phydev, SPEED_1000);
        (void)phy_speed_down(&phydev, false);
        (void)phy_speed_up(&phydev);
        (void)phy_modify(&phydev, 0, 0xff, 1);
        (void)__phy_modify(&phydev, 0, 0xff, 1);
        (void)phy_write_mmd(&phydev, 0, 0, 1);
        (void)__phy_write_mmd(&phydev, 0, 0, 1);
        (void)__phy_modify_mmd(&phydev, 0, 0, 0xff, 1);
        (void)phy_read_paged(&phydev, 0, 0);
        (void)phy_write_paged(&phydev, 0, 0, 1);
        (void)phy_modify_paged(&phydev, 0, 0, 0xff, 1);
        (void)phy_restore_page(&phydev, phy_select_page(&phydev, 0), 0);
        phy_print_status(&phydev);
        phy_attached_info(&phydev);
        phy_mac_interrupt(&phydev);
        phy_disconnect(&phydev);
        (void)netdev_priv(netdev);
        (void)register_netdev(netdev);
        skb = dev_alloc_skb(SAMPLE_SKB_LEN);
        if (skb != NULL) {
            skb_reserve(skb, ETH_HLEN);
            skb_data = skb_put(skb, SAMPLE_SKB_LEN - ETH_HLEN);
            (void)skb_data;
            skb->dev = netdev;
            skb->protocol = ETH_P_IP;
            (void)skb_partial_csum_set(skb, 0, 0);
            (void)skb_copy_bits(skb, 0, skb_copy, 4);
            (void)__pskb_pull_tail(skb, 0);
            skb_trim(skb, SAMPLE_SKB_LEN - ETH_HLEN);
            (void)___pskb_trim(skb, SAMPLE_SKB_LEN - ETH_HLEN);
            (void)__skb_pad(skb, 1, false);
            skb_tstamp_tx(skb, NULL);
            skb_clone_tx_timestamp(skb);
            (void)skb_tail_pointer(skb);
            (void)netif_rx(skb);
        }
        skb = napi_alloc_skb(&napi, SAMPLE_SKB_LEN);
        if (skb != NULL) {
            napi_consume_skb(skb, 1);
        }
        (void)napi_get_frags(&napi);
        (void)napi_gro_frags(&napi);
        (void)__napi_alloc_frag_align(SAMPLE_SKB_LEN, 0);
        (void)skb_page_frag_refill(SAMPLE_SKB_LEN, &s, GFP_KERNEL);
        unregister_netdev(netdev);
        free_netdev(netdev);
    }
    queue = blk_alloc_queue(GFP_KERNEL);
    if (queue != NULL) {
        blk_queue_make_request(queue, sample_make_request);
        blk_queue_logical_block_size(queue, SAMPLE_BLOCK_SIZE);
        disk = alloc_disk(SAMPLE_DISK_MINORS);
        if (disk != NULL) {
            disk->disk_name[0] = 's';
            disk->disk_name[1] = 'd';
            disk->disk_name[2] = 'x';
            disk->disk_name[3] = '\0';
            disk->queue = queue;
            disk->fops = &sample_blk_ops;
            disk->private_data = &s;
            disk->flags = GENHD_FL_NO_PART_SCAN;
            set_capacity(disk, SAMPLE_DISK_SECTORS);
            add_disk(disk);
            (void)get_capacity(disk);
            bdev.bd_disk = disk;
            bdev.bd_queue = queue;
            bdev.bd_private = &s;
            bio = bio_alloc(GFP_KERNEL, SAMPLE_BIO_VECS);
            if (bio != NULL) {
                bio_set_dev(bio, &bdev);
                bio->bi_opf = REQ_OP_FLUSH;
                bio->bi_sector = 0;
                (void)bio_add_page(bio, NULL, SAMPLE_BIO_LEN, 0);
                (void)__bio_add_page(bio, NULL, SAMPLE_BIO_LEN, 0);
                (void)submit_bio(bio);
                submit_bio_noacct(bio);
                (void)submit_bio_wait(bio);
                bio->bi_opf = REQ_OP_DISCARD;
                (void)submit_bio(bio);
                (void)bio_split_to_limits(bio);
                (void)bio_associate_blkg(bio);
                (void)bio_blkcg_css(bio);
                zero_fill_bio_iter(bio);
                bio_chain(bio, bio);
                bio_endio(bio);
                bio_put(bio);
            }
            (void)bdev_disk_changed(disk, false);
            blk_mark_disk_dead(disk);
            del_gendisk(disk);
            put_disk(disk);
        }
        blk_cleanup_queue(queue);
    }
    if (blk_mq_alloc_tag_set(&tag_set) == 0) {
        blk_mq_map_queues(&tag_set);
        mq_queue = blk_mq_alloc_queue(&tag_set, &limits, &s);
        if (mq_queue != NULL) {
            blk_queue_rq_timeout(mq_queue, 1);
            blk_mq_freeze_queue_nomemsave(mq_queue);
            blk_mq_freeze_queue_wait(mq_queue);
            blk_mq_unfreeze_queue_nomemrestore(mq_queue);
            blk_mq_quiesce_queue(mq_queue);
            blk_mq_unquiesce_queue(mq_queue);
            blk_mq_stop_hw_queues(mq_queue);
            blk_mq_start_stopped_hw_queues(mq_queue, false);
            blk_mq_update_nr_hw_queues(&tag_set, SAMPLE_BLK_HW_QUEUES);
            blk_mq_map_hw_queues(NULL, NULL, 0);
            rq = blk_mq_alloc_request(mq_queue, REQ_OP_READ, 0);
            if (rq != NULL) {
                (void)blk_mq_unique_tag(rq);
                blk_execute_rq_nowait(rq, false);
                (void)blk_execute_rq(rq, false);
                (void)blk_update_request(rq, BLK_STS_OK, 0);
                blk_mq_requeue_request(rq, false);
                blk_mq_free_request(rq);
            }
            blk_sync_queue(mq_queue);
            blk_mq_destroy_queue(mq_queue);
        }
        mq_queue = blk_mq_init_queue(&tag_set);
        blk_put_queue(mq_queue);
        mq_disk = blk_mq_alloc_disk(&tag_set, &limits, &s);
        if (mq_disk != NULL) {
            mq_disk->disk_name[0] = 'm';
            mq_disk->disk_name[1] = 'q';
            mq_disk->disk_name[2] = '0';
            mq_disk->disk_name[3] = '\0';
            (void)device_add_disk(&dev, mq_disk, NULL);
            del_gendisk(mq_disk);
            put_disk(mq_disk);
        }
        blk_set_stacking_limits(&limits);
        (void)blk_revalidate_disk_zones(NULL, NULL);
        (void)blk_status_to_errno(BLK_STS_OK);
        (void)errno_to_blk_status(0);
        (void)blk_op_str(REQ_OP_READ);
        blk_mq_quiesce_tagset(&tag_set);
        blk_mq_unquiesce_tagset(&tag_set);
        blk_mq_free_tag_set(&tag_set);
    }
    input_ev.tv_sec = 0;
    input_ev.tv_usec = 0;
    input_ev.type = EV_SYN;
    input_ev.code = SYN_REPORT;
    input_ev.value = 0;
    (void)input_ev;
    input = input_allocate_device();
    if (input != NULL) {
        input->name = "sample-input";
        input->phys = "sample/input0";
        input->uniq = "sample-serial";
        input->id.bustype = BUS_VIRTUAL;
        input->id.vendor = SAMPLE_PCI_VENDOR;
        input->id.product = SAMPLE_PCI_DEVICE;
        input->id.version = 1;
        input_set_capability(input, EV_KEY, KEY_A);
        input_set_capability(input, EV_REL, REL_X);
        input_set_capability(input, EV_LED, LED_NUML);
        input_set_abs_params(input, ABS_X, SAMPLE_ABS_MIN, SAMPLE_ABS_MAX, SAMPLE_ABS_FUZZ, SAMPLE_ABS_FLAT);
        input_set_drvdata(input, &s);
        (void)input_get_drvdata(input);
        (void)test_bit(KEY_A, input->keybit);
        if (input_register_device(input) == 0) {
            input_report_key(input, KEY_A, 1);
            input_report_rel(input, REL_X, 1);
            input_report_abs(input, ABS_X, 10);
            input_event(input, EV_LED, LED_NUML, 1);
            input_sync(input);
            input_unregister_device(input);
        } else {
            input_free_device(input);
        }
    }
    uep.bEndpointAddress = USB_DIR_IN | 1;
    uep.bmAttributes = USB_ENDPOINT_XFER_BULK;
    uep.wMaxPacketSize = 512;
    ualt.desc.bInterfaceClass = USB_CLASS_HID;
    ualt.desc.bInterfaceSubClass = 0;
    ualt.desc.bInterfaceProtocol = 0;
    ualt.endpoint = &uep;
    ualt.extra = NULL;
    ualt.extralen = 0;
    udev.devnum = SAMPLE_USB_DEVNUM;
    udev.speed = USB_SPEED_HIGH;
    udev.descriptor.idVendor = SAMPLE_PCI_VENDOR;
    udev.descriptor.idProduct = SAMPLE_PCI_DEVICE;
    uintf.usb_dev = &udev;
    uintf.altsetting = &ualt;
    uintf.cur_altsetting = &ualt;
    uintf.num_altsetting = 1;
    uintf.intfdata = NULL;
    (void)interface_to_usbdev(&uintf);
    (void)usb_register(&udrv);
    (void)usb_match_id(&uintf, sample_usb_ids);
    (void)usb_find_interface(&udrv, 0);
    urb = usb_alloc_urb(0, GFP_KERNEL);
    if (urb != NULL) {
        usb_fill_bulk_urb(urb, &udev, usb_rcvbulkpipe(&udev, 1), usb_buf, sizeof(usb_buf), NULL, NULL);
        (void)usb_submit_urb(urb, GFP_KERNEL);
        usb_kill_urb(urb);
        (void)usb_unlink_urb(urb);
        usb_free_urb(urb);
    }
    (void)usb_control_msg(&udev, usb_sndctrlpipe(&udev, 0), 0, USB_TYPE_VENDOR | USB_RECIP_DEVICE, 0, 0, usb_buf, sizeof(usb_buf), SAMPLE_USB_TIMEOUT);
    (void)usb_bulk_msg(&udev, usb_rcvbulkpipe(&udev, 1), usb_buf, sizeof(usb_buf), &usb_actual, SAMPLE_USB_TIMEOUT);
    (void)usb_interrupt_msg(&udev, usb_rcvintpipe(&udev, 1), usb_buf, sizeof(usb_buf), &usb_actual, SAMPLE_USB_TIMEOUT);
    coherent = usb_alloc_coherent(&udev, SAMPLE_DMA_SIZE, GFP_KERNEL, &dma);
    usb_free_coherent(&udev, SAMPLE_DMA_SIZE, coherent, dma);
    coherent = usb_buffer_alloc(&udev, SAMPLE_DMA_SIZE, GFP_KERNEL, &dma);
    usb_buffer_free(&udev, SAMPLE_DMA_SIZE, coherent, dma);
    usb_get_dev(&udev);
    usb_put_dev(&udev);
    usb_get_intf(&uintf);
    usb_put_intf(&uintf);
    usb_deregister(&udrv);
    INIT_LIST_HEAD(&gadget_ep.ep_list);
    gadget_ep.name = "ep1in";
    gadget_ep.ops = NULL;
    gadget_ep.caps.type_bulk = 1;
    gadget_ep.caps.dir_in = 1;
    gadget_ep.maxpacket = 512;
    gadget_ep.maxpacket_limit = 512;
    gadget_ep.address = USB_DIR_IN | 1;
    gadget_ep.desc = &uep;
    INIT_LIST_HEAD(&gadget.ep_list);
    gadget.ep0 = &gadget_ep;
    gadget.speed = USB_SPEED_HIGH;
    gadget.max_speed = USB_SPEED_HIGH;
    gadget.name = "sample-gadget";
    (void)usb_gadget_register_driver(&gadget_driver);
    (void)usb_gadget_check_config(&gadget);
    (void)usb_gadget_activate(&gadget);
    (void)usb_gadget_deactivate(&gadget);
    (void)usb_gadget_set_selfpowered(&gadget);
    (void)usb_gadget_clear_selfpowered(&gadget);
    (void)usb_gadget_set_remote_wakeup(&gadget, 1);
    (void)usb_gadget_vbus_draw(&gadget, 250);
    usb_gadget_set_state(&gadget, USB_STATE_CONFIGURED);
    (void)usb_gadget_ep_match_desc(&gadget, &gadget_ep, &uep, NULL);
    (void)usb_speed_string(gadget.speed);
    usb_ep_set_maxpacket_limit(&gadget_ep, 512);
    usb_ep_set_drvdata(&gadget_ep, &gadget);
    (void)usb_ep_get_drvdata(&gadget_ep);
    gadget_req = usb_ep_alloc_request(&gadget_ep, GFP_KERNEL);
    if (gadget_req != NULL) {
        gadget_req->buf = usb_buf;
        gadget_req->length = sizeof(usb_buf);
        (void)usb_ep_queue(&gadget_ep, gadget_req, GFP_KERNEL);
        (void)usb_ep_dequeue(&gadget_ep, gadget_req);
        usb_ep_free_request(&gadget_ep, gadget_req);
    }
    usb_gadget_unregister_driver(&gadget_driver);
    int_to_scsilun(SAMPLE_SCSI_LUN, &scsi_lun);
    scsi_cdb[0] = 0x28;
    (void)scsi_command_size(scsi_cdb);
    (void)scsi_command_size_tbl[scsi_cdb[0] >> 5];
    (void)scsi_device_type[TYPE_DISK];
    (void)scsi_build_sense_buffer(0, scsi_sense, SAMPLE_SCSI_SENSE_KEY, SAMPLE_SCSI_ASC, SAMPLE_SCSI_ASCQ);
    scsi_set_sense_information(scsi_sense, sizeof(scsi_sense), 0x01020304);
    pdev.dev.dma_mask = &dma_mask;
    pdev.dev.coherent_dma_mask = DMA_BIT_MASK(DMA_ULL_BITS);
    pdev.dev.driver_data = NULL;
    pdev.dev.parent = NULL;
    pdev.dev.bus = NULL;
    pdev.dev.class = NULL;
    pdev.dev.driver = NULL;
    pdev.dev.init_name = "sample-pci-dev";
    pdev.dev.release = NULL;
    pdev.vendor = SAMPLE_PCI_VENDOR;
    pdev.device = SAMPLE_PCI_DEVICE;
    pdev.subsystem_vendor = SAMPLE_PCI_SUBVENDOR;
    pdev.subsystem_device = SAMPLE_PCI_SUBDEVICE;
    pdev.class = SAMPLE_PCI_CLASS;
    pdev.bus = SAMPLE_PCI_BUS;
    pdev.devfn = PCI_DEVFN(SAMPLE_PCI_SLOT, SAMPLE_PCI_FUNC);
    pdev.irq = SAMPLE_IRQ;
    pdev.resource[SAMPLE_PCI_BAR].start = SAMPLE_PCI_BAR_START;
    pdev.resource[SAMPLE_PCI_BAR].end = SAMPLE_PCI_BAR_END;
    pdev.resource[SAMPLE_PCI_BAR].name = "sample-bar";
    pdev.resource[SAMPLE_PCI_BAR].flags = IORESOURCE_MEM;
    pdev.config_space[SAMPLE_PCI_CFG_VENDOR_DEVICE] = (SAMPLE_PCI_DEVICE << 16) | SAMPLE_PCI_VENDOR;
    cdev_init(&cdev, &sample_fops);
    (void)register_chrdev_region(MKDEV(SAMPLE_CHRDEV_MAJOR, SAMPLE_CHRDEV_MINOR), SAMPLE_CHRDEV_COUNT, "sample-char");
    (void)cdev_add(&cdev, MKDEV(SAMPLE_CHRDEV_MAJOR, SAMPLE_CHRDEV_MINOR), SAMPLE_CHRDEV_COUNT);
    cdev_del(&cdev);
    unregister_chrdev_region(MKDEV(SAMPLE_CHRDEV_MAJOR, SAMPLE_CHRDEV_MINOR), SAMPLE_CHRDEV_COUNT);
    (void)alloc_chrdev_region(&chrdev_devt, SAMPLE_CHRDEV_MINOR, SAMPLE_CHRDEV_COUNT, "sample-dyn-char");
    unregister_chrdev_region(chrdev_devt, SAMPLE_CHRDEV_COUNT);
    chrdev_major = register_chrdev(0, "sample-legacy-char", &sample_fops);
    unregister_chrdev((unsigned int)chrdev_major, "sample-legacy-char");
    (void)nonseekable_open(NULL, NULL);
    (void)sample_chr_ioctl(NULL, SAMPLE_IOCTL_CMD, 0);
    (void)misc_register(&misc);
    (void)misc_deregister(&misc);
    (void)pci_register_driver(&pdrv);
    (void)pci_enable_device(&pdev);
    pci_set_master(&pdev);
    pci_clear_master(&pdev);
    pci_set_drvdata(&pdev, &s);
    (void)pci_get_drvdata(&pdev);
    (void)pci_name(&pdev);
    (void)pci_resource_start(&pdev, SAMPLE_PCI_BAR);
    (void)pci_resource_end(&pdev, SAMPLE_PCI_BAR);
    (void)pci_resource_flags(&pdev, SAMPLE_PCI_BAR);
    (void)pci_resource_len(&pdev, SAMPLE_PCI_BAR);
    (void)pci_request_region(&pdev, SAMPLE_PCI_BAR, "sample");
    regs = pci_iomap(&pdev, SAMPLE_PCI_BAR, SAMPLE_MMIO_SIZE);
    pci_iounmap(&pdev, regs);
    pci_release_region(&pdev, SAMPLE_PCI_BAR);
    (void)pci_request_regions(&pdev, "sample");
    pci_release_regions(&pdev);
    (void)pci_alloc_irq_vectors(&pdev, SAMPLE_PCI_MIN_VECTORS, SAMPLE_PCI_MAX_VECTORS, PCI_IRQ_LEGACY);
    (void)pci_irq_vector(&pdev, SAMPLE_PCI_FUNC);
    pci_free_irq_vectors(&pdev);
    (void)pci_read_config_byte(&pdev, SAMPLE_PCI_CFG_COMMAND, &pci_cfg8);
    (void)pci_read_config_word(&pdev, SAMPLE_PCI_CFG_COMMAND, &pci_cfg16);
    (void)pci_read_config_dword(&pdev, SAMPLE_PCI_CFG_COMMAND, &pci_cfg32);
    (void)pci_write_config_byte(&pdev, SAMPLE_PCI_CFG_COMMAND, pci_cfg8);
    (void)pci_write_config_word(&pdev, SAMPLE_PCI_CFG_COMMAND, pci_cfg16);
    (void)pci_write_config_dword(&pdev, SAMPLE_PCI_CFG_COMMAND, pci_cfg32);
    (void)pci_save_state(&pdev);
    (void)pci_set_power_state(&pdev, PCI_D3hot);
    (void)pci_choose_state(&pdev, PMSG_SUSPEND);
    (void)pci_enable_wake(&pdev, PCI_D3hot, true);
    (void)pci_restore_state(&pdev);
    (void)pci_set_power_state(&pdev, PCI_D0);
    pci_disable_device(&pdev);
    pci_unregister_driver(&pdrv);
    plat_resources[SAMPLE_PLATFORM_MEM_RESOURCE].start = SAMPLE_PCI_BAR_START;
    plat_resources[SAMPLE_PLATFORM_MEM_RESOURCE].end = SAMPLE_PCI_BAR_END;
    plat_resources[SAMPLE_PLATFORM_MEM_RESOURCE].name = "sample-mmio";
    plat_resources[SAMPLE_PLATFORM_MEM_RESOURCE].flags = IORESOURCE_MEM;
    plat_resources[1].start = SAMPLE_IRQ;
    plat_resources[1].end = SAMPLE_IRQ;
    plat_resources[1].name = "sample-irq";
    plat_resources[1].flags = IORESOURCE_IRQ;
    of_node.name = "sample-platform";
    of_node.type = "platform";
    of_node.compatible = "oxide,sample-platform";
    of_node.data = NULL;
    acpi_dev.hid[0] = 'O';
    acpi_dev.hid[1] = 'X';
    acpi_dev.hid[2] = 'I';
    acpi_dev.hid[3] = 'D';
    acpi_dev.hid[4] = '0';
    acpi_dev.hid[5] = '0';
    acpi_dev.hid[6] = '0';
    acpi_dev.hid[7] = '1';
    acpi_dev.hid[8] = '\0';
    acpi_dev.uid[0] = '0';
    acpi_dev.uid[1] = '\0';
    acpi_dev.driver_data = NULL;
    platdev.name = "sample-platform";
    platdev.id = PLATFORM_DEVID_NONE;
    platdev.dev.init_name = "sample-platform";
    platdev.dev.of_node = &of_node;
    platdev.dev.acpi_node = &acpi_dev;
    platdev.num_resources = ARRAY_SIZE(plat_resources);
    platdev.resource = plat_resources;
    platdev.driver_data = NULL;
    platdev.driver = NULL;
    platdev.id_entry = NULL;
    platdev.registered = 0;
    (void)platform_driver_register(&pldrv);
    (void)platform_device_register(&platdev);
    plat_res = platform_get_resource(&platdev, IORESOURCE_MEM, SAMPLE_PLATFORM_MEM_RESOURCE);
    (void)platform_get_resource_byname(&platdev, IORESOURCE_MEM, "sample-mmio");
    (void)platform_get_irq(&platdev, SAMPLE_PLATFORM_IRQ_RESOURCE);
    regs = devm_platform_ioremap_resource(&platdev, SAMPLE_PLATFORM_MEM_RESOURCE);
    (void)devm_platform_get_and_ioremap_resource(&platdev, SAMPLE_PLATFORM_MEM_RESOURCE, &plat_res);
    (void)regs;
    (void)of_match_device(sample_of_ids, &platdev.dev);
    (void)acpi_match_device(sample_acpi_ids, &platdev.dev);
    (void)acpi_dev_get_first_match_dev("OXID0001", "0", 0);
    acpi_dev_put(&acpi_dev);
    (void)of_property_read_u32(&of_node, "clock-frequency", &pci_cfg32);
    (void)of_property_read_bool(&of_node, "dma-coherent");
    match_data = device_get_match_data(&platdev.dev);
    (void)match_data;
    platform_device_unregister(&platdev);
    platform_driver_unregister(&pldrv);
    (void)dma_set_mask_and_coherent(&dev, DMA_BIT_MASK(DMA_ULL_BITS));
    coherent = dma_alloc_coherent(&dev, SAMPLE_DMA_SIZE, &dma, GFP_KERNEL);
    (void)dma_mapping_error(&dev, dma);
    dma_sync_single_for_device(&dev, dma, SAMPLE_DMA_SIZE, DMA_TO_DEVICE);
    dma_sync_single_for_cpu(&dev, dma, SAMPLE_DMA_SIZE, DMA_FROM_DEVICE);
    dma_free_coherent(&dev, SAMPLE_DMA_SIZE, coherent, dma);
    dma = dma_map_single(&dev, dma_buf, sizeof(dma_buf), DMA_BIDIRECTIONAL);
    dma_unmap_single(&dev, dma, sizeof(dma_buf), DMA_BIDIRECTIONAL);
    page = alloc_pages(GFP_KERNEL, SAMPLE_DMA_PAGE_ORDER);
    dma = dma_map_page(&dev, page, SAMPLE_DMA_PAGE_OFFSET, SAMPLE_DMA_SIZE, DMA_FROM_DEVICE);
    dma_unmap_page(&dev, dma, SAMPLE_DMA_SIZE, DMA_FROM_DEVICE);
    sg_init_table(sg, ARRAY_SIZE(sg));
    sg_set_buf(&sg[0], dma_buf, sizeof(dma_buf));
    sg_set_page(&sg[1], page, SAMPLE_DMA_SIZE, SAMPLE_DMA_PAGE_OFFSET);
    (void)sg_next(&sg[0]);
    (void)sg_copy_to_buffer(sg, ARRAY_SIZE(sg), dma_buf, sizeof(dma_buf));
    (void)sg_alloc_table(&sg_table, ARRAY_SIZE(sg), GFP_KERNEL);
    sg_free_table(&sg_table);
    sg_miter_start(&sg_iter, sg, ARRAY_SIZE(sg), SG_MITER_FROM_SG);
    (void)sg_miter_next(&sg_iter);
    sg_miter_stop(&sg_iter);
    sg_allocated = sgl_alloc_order(SAMPLE_DMA_SIZE, SAMPLE_DMA_PAGE_ORDER, false, GFP_KERNEL, &sg_allocated_nents);
    sgl_free_n_order(sg_allocated, sg_allocated_nents, SAMPLE_DMA_PAGE_ORDER);
    (void)dma_map_sg(&dev, sg, ARRAY_SIZE(sg), DMA_TO_DEVICE);
    dma_sync_sg_for_device(&dev, sg, ARRAY_SIZE(sg), DMA_TO_DEVICE);
    dma_sync_sg_for_cpu(&dev, sg, ARRAY_SIZE(sg), DMA_FROM_DEVICE);
    dma_unmap_sg(&dev, sg, ARRAY_SIZE(sg), DMA_TO_DEVICE);
    __free_pages(page, SAMPLE_DMA_PAGE_ORDER);
    regs = ioremap(0, SAMPLE_MMIO_SIZE);
    (void)readb(regs);
    (void)readw(regs);
    (void)readl(regs);
    (void)readq(regs);
    writeb(SAMPLE_WRITEB, regs);
    writew(SAMPLE_WRITEW, regs);
    writel(SAMPLE_WRITEL, regs);
    writeq(SAMPLE_WRITEQ, regs);
    memcpy_toio(regs, &s, sizeof(s));
    memcpy_fromio(&s, regs, sizeof(s));
    memset_io(regs, 0, sizeof(s));
    port8 = inb(SAMPLE_IO_PORT);
    outb(port8, SAMPLE_IO_PORT);
    (void)inw(SAMPLE_IO_PORT);
    (void)inl(SAMPLE_IO_PORT);
    outw(0, SAMPLE_IO_PORT);
    outl(0, SAMPLE_IO_PORT);
    mb();
    rmb();
    wmb();
    mmiowb();
    iounmap(regs);
    (void)jiffies;
    (void)msecs_to_jiffies(10);
    (void)__msecs_to_jiffies(10);
    (void)usecs_to_jiffies(10);
    (void)__usecs_to_jiffies(10);
    (void)nsecs_to_jiffies(10);
    (void)jiffies_to_msecs(1);
    (void)jiffies_to_usecs(1);
    (void)round_jiffies(1);
    (void)ktime_get();
    (void)ktime_get_ns();
    (void)ktime_get_with_offset(0);
    ktime_get_ts64(&ts64);
    ktime_get_raw_ts64(&ts64);
    ktime_get_real_ts64(&ts64);
    (void)ktime_set(1, 2);
    (void)ktime_add_ns(ns_to_ktime(1), 1);
    (void)ktime_sub_ns(ns_to_ktime(2), 1);
    (void)ktime_to_ns(ns_to_ktime(1));
    msleep(1);
    (void)msleep_interruptible(1);
    usleep_range(10, 20);
    usleep_range_state(10, 20, TASK_INTERRUPTIBLE);
    udelay(1);
    __udelay(1);
    __const_udelay(1);
    mdelay(1);
    init_timer(&timer);
    timer_init_key(&timer, sample_timer_fn, 0, "sample", NULL);
    timer_setup(&timer, sample_timer_fn, 0);
    timer.expires = jiffies + msecs_to_jiffies(1);
    add_timer(&timer);
    (void)mod_timer(&timer, jiffies + 1);
    (void)timer_reduce(&timer, jiffies + 1);
    (void)del_timer(&timer);
    (void)timer_delete(&timer);
    (void)timer_delete_sync(&timer);
    (void)timer_shutdown_sync(&timer);
    (void)del_timer_sync(&timer);
    hrtimer_init(&hrtimer, 0, HRTIMER_MODE_REL);
    hrtimer.function = sample_hrtimer_fn;
    (void)hrtimer_start(&hrtimer, ns_to_ktime(1), HRTIMER_MODE_REL);
    hrtimer_setup(&hrtimer, sample_hrtimer_fn, HRTIMER_MODE_REL);
    hrtimer_start_range_ns(&hrtimer, ns_to_ktime(1), 1, HRTIMER_MODE_REL);
    (void)hrtimer_active(&hrtimer);
    (void)hrtimer_forward(&hrtimer, ns_to_ktime(1), ns_to_ktime(1));
    (void)hrtimer_cancel(&hrtimer);
    wq = alloc_workqueue("sample", 0, 1);
    INIT_WORK(&sample_work, NULL);
    (void)schedule_work(&sample_work);
    (void)queue_work_on(0, wq, &sample_work);
    (void)flush_work(&sample_work);
    flush_scheduled_work();
    __flush_workqueue(wq);
    disable_work(&sample_work);
    (void)disable_work_sync(&sample_work);
    enable_work(&sample_work);
    (void)cancel_work_sync(&sample_work);
    INIT_DELAYED_WORK(&delayed, NULL);
    (void)schedule_delayed_work(&delayed, 1);
    (void)queue_delayed_work_on(0, wq, &delayed, 1);
    (void)mod_delayed_work_on(0, wq, &delayed, 1);
    (void)cancel_delayed_work(&delayed);
    delayed_work_timer_fn(&delayed.timer);
    (void)cancel_delayed_work_sync(&delayed);
    destroy_workqueue(wq);
    task = kthread_run(sample_thread, &s, "sample");
    kthread_associate_blkcg(NULL);
    (void)kthread_should_stop();
    (void)kthread_stop(task);
    set_current_state(TASK_INTERRUPTIBLE);
    schedule();
    (void)schedule_timeout(1);
    tasklet_init(&sample_tasklet, NULL, 0);
    tasklet_schedule(&sample_tasklet);
    tasklet_disable(&sample_tasklet);
    tasklet_enable(&sample_tasklet);
    tasklet_kill(&sample_tasklet);
    spin_lock_init(&spl);
    spin_lock(&spl);
    spin_unlock(&spl);
    raw_spin_lock_init(&raw);
    (void)raw_spin_trylock(&raw);
    raw_spin_unlock(&raw);
    _raw_spin_lock_bh(&raw);
    _raw_spin_unlock_bh(&raw);
    _raw_spin_lock_irq(&raw);
    _raw_spin_unlock_irq(&raw);
    start = _raw_spin_lock_irqsave(&raw);
    _raw_spin_unlock_irqrestore(&raw, start);
    mutex_init(&m);
    __mutex_init(&m, "sample", NULL);
    mutex_lock(&m);
    mutex_unlock(&m);
    (void)mutex_lock_interruptible(&m);
    mutex_unlock(&m);
    rwlock_init(&rwl);
    read_lock(&rwl);
    read_unlock(&rwl);
    write_lock(&rwl);
    write_unlock(&rwl);
    init_rwsem(&sem);
    down_read(&sem);
    up_read(&sem);
    down_write(&sem);
    up_write(&sem);
    sema_init(&semaphore, 1);
    down(&semaphore);
    up(&semaphore);
    (void)down_interruptible(&semaphore);
    up(&semaphore);
    (void)down_trylock(&semaphore);
    up(&semaphore);
    seqlock_init(&seq);
    start = read_seqbegin(&seq);
    (void)read_seqretry(&seq, start);
    init_completion(&comp);
    complete(&comp);
    (void)try_wait_for_completion(&comp);
    (void)wait_for_completion_interruptible(&comp);
    (void)wait_for_completion_timeout(&comp, 1);
    init_waitqueue_head(&wait);
    __init_waitqueue_head(&wait, "sample_wait", NULL);
    __init_swait_queue_head(&swait, "sample_swait", NULL);
    wake_up(&wait);
    (void)__wake_up(&wait, TASK_INTERRUPTIBLE, 1, NULL);
    (void)waitqueue_active(&wait);
    init_wait_entry(&wait_entry, 0);
    (void)prepare_to_wait_event(&wait, &wait_entry, TASK_INTERRUPTIBLE);
    finish_wait(&wait, &wait_entry);
    __rcu_read_lock();
    __rcu_read_unlock();
    synchronize_rcu();
    rcu_barrier();
    atomic_set(&atom, 1);
    atomic_inc(&atom);
    (void)atomic_dec_and_test(&atom);
    refcount_set(&refs, 1);
    refcount_inc(&refs);
    (void)refcount_dec_and_test(&refs);
    owner.state = 0;
    owner.refcnt = 1;
    (void)try_module_get(&owner);
    module_put(&owner);
    (void)param_set_bool("Y", &param_bool_kp);
    (void)param_get_bool(param_buf, &param_bool_kp);
    (void)param_set_int("-7", &param_int_kp);
    (void)param_get_int(param_buf, &param_int_kp);
    (void)param_set_uint("42", &param_uint_kp);
    (void)param_get_uint(param_buf, &param_uint_kp);
    (void)param_set_ulong("123", &param_ulong_kp);
    (void)param_get_ulong(param_buf, &param_ulong_kp);
    (void)param_array_ops.set("1,2,3", &param_arr_kp);
    (void)param_array_ops.get(param_buf, &param_arr_kp);
    kref_init(&kref);
    kref_get(&kref);
    (void)kref_put(&kref, sample_release);
    lockdep_set_class(&spl, &key);
    (void)sample_xa;
    (void)sample_idr;
    return 0;
}

static void __exit sample_exit(void) {}

module_init(sample_init);
module_exit(sample_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("oxide");
MODULE_DESCRIPTION("kpi header smoke");
