#include <linux/bitmap.h>
#include <linux/blkdev.h>
#include <linux/atomic.h>
#include <linux/acpi.h>
#include <linux/completion.h>
#include <linux/configfs.h>
#include <linux/crc32.h>
#include <linux/crc32c.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
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
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/pm.h>
#include <linux/pm_runtime.h>
#include <linux/pm_wakeup.h>
#include <linux/refcount.h>
#include <linux/random.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/rwsem.h>
#include <linux/seqlock.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/suspend.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
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
static const u8 sample_mac[ETH_ALEN] = { 0x02, 0x4f, 0x58, 0x00, 0x00, 0x01 };
static void sample_release(struct kref *kref) { (void)kref; }
static int sample_thread(void *data) { return data != NULL; }
static void sample_timer_fn(struct timer_list *timer) { (void)timer; }
static enum hrtimer_restart sample_hrtimer_fn(struct hrtimer *timer) { (void)timer; return HRTIMER_NORESTART; }
static irqreturn_t sample_irq_handler(int irq, void *dev) { (void)irq; (void)dev; return IRQ_HANDLED; }
static void sample_devres_action(void *data) { (void)data; }
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
static int sample_net_open(struct net_device *dev) { (void)dev; return 0; }
static int sample_net_stop(struct net_device *dev) { (void)dev; return 0; }
static int sample_make_request(struct request_queue *queue, struct bio *bio)
{
    (void)queue;
    bio->bi_status = BLK_STS_OK;
    return bio_op(bio) == REQ_OP_DISCARD ? 0 : (int)bio->bi_size;
}
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
};
static const struct block_device_operations sample_blk_ops = {
    .owner = THIS_MODULE,
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
};

static int __init sample_init(void)
{
    struct sample s;
    spinlock_t spl;
    raw_spinlock_t raw;
    struct mutex m;
    rwlock_t rwl;
    struct rw_semaphore sem;
    seqlock_t seq;
    struct completion comp;
    wait_queue_head_t wait;
    struct timer_list timer;
    struct hrtimer hrtimer;
    struct delayed_work delayed;
    struct task_struct *task;
    struct scatterlist sg[SAMPLE_DMA_SG_NENTS];
    struct device dev;
    struct class *class;
    struct bus_type bus = { "sample-bus", NULL };
    struct device_driver driver = { "sample-driver", &bus, THIS_MODULE, NULL, NULL };
    struct device *root_dev;
    struct device *created_dev;
    struct dentry *debug_dir;
    struct dentry *debug_file;
    struct dentry *debug_blob_file;
    struct dentry *debug_link;
    struct debugfs_blob_wrapper debug_blob;
    u32 debug_value = SAMPLE_DEBUG_VALUE_INIT;
    char debug_blob_data[4] = { 'd', 'a', 't', 'a' };
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
    struct request_queue *queue;
    struct request_queue *mq_queue;
    struct gendisk *disk;
    struct bio *bio;
    struct block_device bdev;
    struct blk_mq_tag_set tag_set = {
        NULL, SAMPLE_BLK_HW_QUEUES, SAMPLE_BLK_QUEUE_DEPTH,
        0, 0, 0, &s
    };
    struct input_dev *input;
    struct input_event input_ev;
    struct usb_device udev;
    struct usb_interface uintf;
    struct usb_host_interface ualt;
    struct usb_endpoint_descriptor uep;
    struct usb_driver udrv = {
        .name = "sample-usb",
        .probe = sample_usb_probe,
        .disconnect = sample_usb_disconnect,
        .id_table = sample_usb_ids,
    };
    struct urb *urb;
    struct pci_driver pdrv = {
        "sample-pci", sample_pci_ids, sample_pci_probe, sample_pci_remove,
        { "sample-pci", NULL, THIS_MODULE, NULL, NULL }
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
    struct lock_class_key key;
    unsigned int start;
    void __iomem *regs;
    const void *match_data;
    u8 port8;
    u8 pci_cfg8;
    u16 pci_cfg16;
    u32 pci_cfg32;
    u32 crc;
    u8 random_buf[SAMPLE_RANDOM_LEN];
    u8 digest[SAMPLE_CRYPTO_DIGEST_LEN];
    u8 usercopy_src[SAMPLE_USERCOPY_LEN];
    u8 usercopy_dst[SAMPLE_USERCOPY_LEN];
    u32 user_value;
    u32 __user *user_value_ptr;
    struct crypto_shash *shash;
    struct shash_desc shash_desc;
    int usb_actual;
    char usb_buf[SAMPLE_USB_BULK_LEN];
    INIT_LIST_HEAD(&s.link);
    list_add(&s.link, &samples);
    set_bit(3, sample_bits);
    pr_info("sample %d\n", test_bit(3, sample_bits));
    (void)container_of(&s.link, struct sample, link);
    (void)kmalloc(16, GFP_KERNEL);
    (void)kzalloc(16, GFP_KERNEL);
    (void)kcalloc(2, 8, GFP_KERNEL);
    kfree(NULL);
    (void)vmalloc(SAMPLE_MMIO_SIZE);
    vfree(NULL);
    (void)alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
    (void)__get_free_pages(GFP_KERNEL, 0);
    free_pages(0, 0);
    (void)page_address(NULL);
    (void)page_to_phys(NULL);
    (void)kstrdup("driver", GFP_KERNEL);
    (void)kasprintf(GFP_KERNEL, "driver %d", 1);
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
    debug_blob.data = debug_blob_data;
    debug_blob.size = sizeof(debug_blob_data);
    debug_blob_file = debugfs_create_blob("blob", 0400, debug_dir, &debug_blob);
    debug_link = debugfs_create_symlink("link", debug_dir, "value");
    debugfs_remove(debug_link);
    debugfs_remove(debug_blob_file);
    debugfs_remove(debug_file);
    debugfs_remove_recursive(debug_dir);
    config_group_init_type_name(&sample_config_child, "child", &sample_config_child_type);
    config_group_init_type_name(&subsys.su_group, "sample", &sample_config_type);
    (void)configfs_register_subsystem(&subsys);
    (void)configfs_create_link(&subsys.su_group.item, &sample_config_child.item, "child_link");
    configfs_drop_link(&subsys.su_group.item, &sample_config_child.item, "child_link");
    (void)config_item_get(&subsys.su_group.item);
    config_item_put(&subsys.su_group.item);
    configfs_unregister_subsystem(&subsys);
    (void)request_firmware(&fw, "sample/fw.bin", &dev);
    (void)request_firmware_direct(&fw, "sample/fw.bin", &dev);
    (void)firmware_request(&fw, "sample/fw.bin", &dev);
    (void)firmware_request_nowarn(&fw, "sample/fw.bin", &dev);
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
        netif_carrier_off(netdev);
        netif_carrier_on(netdev);
        (void)netdev_priv(netdev);
        (void)register_netdev(netdev);
        skb = dev_alloc_skb(SAMPLE_SKB_LEN);
        if (skb != NULL) {
            skb_reserve(skb, ETH_HLEN);
            skb_data = skb_put(skb, SAMPLE_SKB_LEN - ETH_HLEN);
            (void)skb_data;
            skb->dev = netdev;
            skb->protocol = ETH_P_IP;
            (void)skb_tail_pointer(skb);
            (void)netif_rx(skb);
        }
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
                (void)submit_bio(bio);
                bio->bi_opf = REQ_OP_DISCARD;
                (void)submit_bio(bio);
                bio_put(bio);
            }
            del_gendisk(disk);
            put_disk(disk);
        }
        blk_cleanup_queue(queue);
    }
    if (blk_mq_alloc_tag_set(&tag_set) == 0) {
        mq_queue = blk_mq_init_queue(&tag_set);
        blk_cleanup_queue(mq_queue);
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
    (void)jiffies_to_msecs(1);
    (void)ktime_get();
    (void)ktime_get_ns();
    (void)ktime_add_ns(ns_to_ktime(1), 1);
    msleep(1);
    usleep_range(10, 20);
    udelay(1);
    mdelay(1);
    timer_setup(&timer, sample_timer_fn, 0);
    timer.expires = jiffies + msecs_to_jiffies(1);
    add_timer(&timer);
    (void)mod_timer(&timer, jiffies + 1);
    (void)del_timer_sync(&timer);
    hrtimer_init(&hrtimer, 0, HRTIMER_MODE_REL);
    hrtimer.function = sample_hrtimer_fn;
    (void)hrtimer_start(&hrtimer, ns_to_ktime(1), HRTIMER_MODE_REL);
    (void)hrtimer_cancel(&hrtimer);
    INIT_WORK(&sample_work, NULL);
    (void)schedule_work(&sample_work);
    flush_scheduled_work();
    (void)cancel_work_sync(&sample_work);
    INIT_DELAYED_WORK(&delayed, NULL);
    (void)schedule_delayed_work(&delayed, 1);
    (void)cancel_delayed_work_sync(&delayed);
    task = kthread_run(sample_thread, &s, "sample");
    (void)kthread_should_stop();
    (void)kthread_stop(task);
    set_current_state(TASK_INTERRUPTIBLE);
    schedule();
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
    mutex_init(&m);
    mutex_lock(&m);
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
    seqlock_init(&seq);
    start = read_seqbegin(&seq);
    (void)read_seqretry(&seq, start);
    init_completion(&comp);
    complete(&comp);
    (void)try_wait_for_completion(&comp);
    init_waitqueue_head(&wait);
    wake_up(&wait);
    (void)waitqueue_active(&wait);
    atomic_set(&atom, 1);
    atomic_inc(&atom);
    (void)atomic_dec_and_test(&atom);
    refcount_set(&refs, 1);
    refcount_inc(&refs);
    (void)refcount_dec_and_test(&refs);
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
