# Syscall and fault cost vs the host Linux kernel

oxide: /tmp/oxide-perf-b2812-repeat.log
boot totals: 1365739 syscalls, 6510 ms on CPU, 4766 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 20,711 | 788 | 26x | ###### | SEVERE |
| recvfrom | 14,402 | 776 | 19x | #### | BAD |
| munmap | 23,708 | 1,382 | 17x | #### | BAD |
| recvmsg | 8,762 | 776 | 11x | ### | BAD |
| write fault, page absent | 12,620 | 1,227 | 10x | ## | BAD |
| read | 4,683 | 518 | 9x | ## | BAD |
| openat | 8,694 | 994 | 9x | ## | BAD |
| mprotect | 7,863 | 1,180 | 7x | ## | BAD |
| mmap | 8,872 | 1,382 | 6x | ## | BAD |
| close | 3,850 | 628 | 6x | # | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,698,371 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 503 | 957.6 us |
| write | 8,343 | 2,597 | 311.4 us |
| other | 2 | 0 | 36.2 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
