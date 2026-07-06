#include <linux/bitmap.h>
#include <linux/gfp.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
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

static int __init sample_init(void)
{
    struct sample s;
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
