# Syscall and fault cost vs the host Linux kernel

oxide: /tmp/B2812-perf.log
boot totals: 4963524 syscalls, 9758 ms on CPU, 1966 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 21,205 | 788 | 27x | ###### | SEVERE |
| recvfrom | 16,175 | 776 | 21x | ##### | SEVERE |
| munmap | 25,944 | 1,382 | 19x | ##### | BAD |
| mprotect | 22,123 | 1,180 | 19x | #### | BAD |
| write fault, page absent | 14,703 | 1,227 | 12x | ### | BAD |
| openat | 9,855 | 994 | 10x | ## | BAD |
| read | 4,696 | 518 | 9x | ## | BAD |
| recvmsg | 6,265 | 776 | 8x | ## | BAD |
| mmap | 9,659 | 1,382 | 7x | ## | BAD |
| close | 3,259 | 628 | 5x | # | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,341,093 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 488 | 929.3 us |
| write | 7,900 | 2,035 | 257.7 us |
| flush | 26 | 140 | 5396.1 us |
| other | 2 | 0 | 9.3 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
