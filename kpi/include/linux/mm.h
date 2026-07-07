#ifndef OXIDE_LINUX_MM_H
#define OXIDE_LINUX_MM_H

#include <linux/gfp.h>
#include <linux/types.h>

struct page *alloc_pages(gfp_t gfp_mask, unsigned int order);
struct page *alloc_pages_noprof(gfp_t gfp_mask, unsigned int order);
struct page *__alloc_pages_noprof(gfp_t gfp_mask, unsigned int order, int preferred_nid, void *nodemask);
void __free_pages(struct page *page, unsigned int order);
unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);
unsigned long get_free_pages(gfp_t gfp_mask, unsigned int order);
void free_pages(unsigned long addr, unsigned int order);
void *page_address(const struct page *page);
unsigned long page_to_phys(const struct page *page);

#endif
