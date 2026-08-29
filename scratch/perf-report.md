# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64.log
boot totals: 1367839 syscalls, 6548 ms on CPU, 4787 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 19,470 | 788 | 25x | ###### | SEVERE |
| recvfrom | 14,214 | 776 | 18x | #### | BAD |
| munmap | 23,728 | 1,382 | 17x | #### | BAD |
| write fault, page absent | 16,153 | 1,227 | 13x | ### | BAD |
| recvmsg | 7,787 | 776 | 10x | ## | BAD |
| read | 5,128 | 518 | 10x | ## | BAD |
| openat | 8,751 | 994 | 9x | ## | BAD |
| mprotect | 7,966 | 1,180 | 7x | ## | BAD |
| close | 3,957 | 628 | 6x | ## | BAD |
| mmap | 5,930 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,045,455 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 387 | 736.3 us |
| write | 8,418 | 2,694 | 320.1 us |
| other | 2 | 0 | 28.9 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
