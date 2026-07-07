#include <linux/bitmap.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/gfp.h>
#include <linux/hrtimer.h>
#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/rwsem.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

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
enum { SAMPLE_WRITEB = 1, SAMPLE_WRITEW = 2, SAMPLE_WRITEL = 3, SAMPLE_WRITEQ = 4 };
static void sample_release(struct kref *kref) { (void)kref; }
static int sample_thread(void *data) { return data != NULL; }
static void sample_timer_fn(struct timer_list *timer) { (void)timer; }
static enum hrtimer_restart sample_hrtimer_fn(struct hrtimer *timer) { (void)timer; return HRTIMER_NORESTART; }
static irqreturn_t sample_irq_handler(int irq, void *dev) { (void)irq; (void)dev; return IRQ_HANDLED; }
static void sample_devres_action(void *data) { (void)data; }
static ssize_t sample_attr_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    (void)dev; (void)attr; (void)buf; return 0;
}
static DEVICE_ATTR(sample, SAMPLE_ATTR_MODE, sample_attr_show, NULL);

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
    struct page *page;
    dma_addr_t dma;
    u64 dma_mask;
    void *coherent;
    char dma_buf[SAMPLE_DMA_BUF_SIZE];
    atomic_t atom;
    refcount_t refs;
    struct kref kref;
    struct lock_class_key key;
    unsigned int start;
    void __iomem *regs;
    u8 port8;
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
    (void)request_threaded_irq(SAMPLE_IRQ, sample_irq_handler, sample_irq_handler, IRQF_ONESHOT, "sample", &s);
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
    device_initialize(&dev);
    (void)dev_set_name(&dev, "sample%d", 1);
    (void)device_add(&dev);
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
