#include <linux/bitmap.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/gfp.h>
#include <linux/idr.h>
#include <linux/kref.h>
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
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>

struct sample {
    int value;
    struct list_head link;
    struct rb_node node;
};

static LIST_HEAD(samples);
static DEFINE_XARRAY(sample_xa);
static DEFINE_IDR(sample_idr);
static DECLARE_BITMAP(sample_bits, 128);
static void sample_release(struct kref *kref) { (void)kref; }

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
    atomic_t atom;
    refcount_t refs;
    struct kref kref;
    struct lock_class_key key;
    unsigned int start;
    INIT_LIST_HEAD(&s.link);
    list_add(&s.link, &samples);
    set_bit(3, sample_bits);
    pr_info("sample %d\n", test_bit(3, sample_bits));
    (void)container_of(&s.link, struct sample, link);
    (void)kmalloc(16, GFP_KERNEL);
    (void)kzalloc(16, GFP_KERNEL);
    (void)kcalloc(2, 8, GFP_KERNEL);
    kfree(NULL);
    (void)vmalloc(4096);
    vfree(NULL);
    (void)alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
    (void)__get_free_pages(GFP_KERNEL, 0);
    free_pages(0, 0);
    (void)page_address(NULL);
    (void)page_to_phys(NULL);
    (void)kstrdup("driver", GFP_KERNEL);
    (void)kasprintf(GFP_KERNEL, "driver %d", 1);
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
