# Syscall and fault cost vs the host Linux kernel

oxide: /tmp/B2812-dcache.log
boot totals: 1365351 syscalls, 6602 ms on CPU, 4836 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 20,704 | 788 | 26x | ###### | SEVERE |
| recvfrom | 16,582 | 776 | 21x | ##### | SEVERE |
| munmap | 24,011 | 1,382 | 17x | #### | BAD |
| mprotect | 20,038 | 1,180 | 17x | #### | BAD |
| recvmsg | 8,906 | 776 | 11x | ### | BAD |
| read | 4,966 | 518 | 10x | ## | BAD |
| openat | 9,162 | 994 | 9x | ## | BAD |
| write fault, page absent | 10,558 | 1,227 | 9x | ## | BAD |
| mmap | 9,476 | 1,382 | 7x | ## | BAD |
| close | 3,509 | 628 | 6x | # | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,243,049 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 431 | 821.2 us |
| write | 8,550 | 2,520 | 294.8 us |
| flush | 27 | 180 | 6694.2 us |
| other | 2 | 0 | 30.0 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
