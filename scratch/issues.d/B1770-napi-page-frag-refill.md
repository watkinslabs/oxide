# B1770 — NAPI page-fragment refill ownership

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | DEFECT | med | Repair `skb_page_frag_refill` so it preserves the Linux `struct page_frag` ABI and page ownership instead of allocating-and-losing a raw buffer. | The current implementation only null-checks `page_frag`, allocates raw storage, drops it, and returns success. The in-tree Linux implementation maintains `page`, `offset`, and `size`, reusing a live fragment before allocating a page. | unowned |
