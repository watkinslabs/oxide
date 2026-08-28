# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2812/target/perf-report-x86.log
boot totals: 1367133 syscalls, 6713 ms on CPU, 4910 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 21,010 | 788 | 27x | ###### | SEVERE |
| recvfrom | 15,655 | 776 | 20x | ##### | SEVERE |
| mprotect | 21,493 | 1,180 | 18x | #### | BAD |
| munmap | 24,683 | 1,382 | 18x | #### | BAD |
| read | 5,662 | 518 | 11x | ### | BAD |
| write fault, page absent | 12,740 | 1,227 | 10x | ## | BAD |
| openat | 9,212 | 994 | 9x | ## | BAD |
| recvmsg | 6,539 | 776 | 8x | ## | BAD |
| mmap | 10,920 | 1,382 | 8x | ## | BAD |
| close | 3,470 | 628 | 6x | # | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,244,473 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 559 | 1063.8 us |
| write | 7,961 | 2,172 | 272.9 us |
| other | 2 | 0 | 12.2 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
