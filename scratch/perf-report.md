# Syscall and fault cost vs the host Linux kernel

oxide: /tmp/oxide-perf-b2812-deferred.log
boot totals: 1365854 syscalls, 6521 ms on CPU, 4774 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 21,128 | 788 | 27x | ###### | SEVERE |
| recvfrom | 13,696 | 776 | 18x | #### | BAD |
| munmap | 22,629 | 1,382 | 16x | #### | BAD |
| write fault, page absent | 14,606 | 1,227 | 12x | ### | BAD |
| recvmsg | 7,301 | 776 | 9x | ## | BAD |
| read | 4,782 | 518 | 9x | ## | BAD |
| openat | 8,718 | 994 | 9x | ## | BAD |
| mprotect | 8,254 | 1,180 | 7x | ## | BAD |
| mmap | 8,836 | 1,382 | 6x | ## | BAD |
| close | 3,698 | 628 | 6x | # | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,713,962 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 366 | 696.9 us |
| write | 8,269 | 3,098 | 374.8 us |
| other | 2 | 0 | 29.1 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
