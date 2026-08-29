# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64.log
boot totals: 1368031 syscalls, 6380 ms on CPU, 4663 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 19,814 | 788 | 25x | ###### | SEVERE |
| recvfrom | 14,054 | 776 | 18x | #### | BAD |
| munmap | 23,376 | 1,382 | 17x | #### | BAD |
| write fault, page absent | 14,577 | 1,227 | 12x | ### | BAD |
| recvmsg | 8,534 | 776 | 11x | ### | BAD |
| read | 5,004 | 518 | 10x | ## | BAD |
| openat | 8,918 | 994 | 9x | ## | BAD |
| mprotect | 8,031 | 1,180 | 7x | ## | BAD |
| close | 3,805 | 628 | 6x | # | BAD |
| mmap | 5,923 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,043,500 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 246 | 468.8 us |
| write | 8,152 | 2,870 | 352.2 us |
| other | 2 | 0 | 23.8 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
