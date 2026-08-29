# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-e4-08-rwsem-fast-reader-r2.log
boot totals: 1367452 syscalls, 6576 ms on CPU, 4809 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 18,627 | 788 | 24x | ###### | SEVERE |
| recvfrom | 15,010 | 776 | 19x | ##### | BAD |
| munmap | 24,903 | 1,382 | 18x | #### | BAD |
| recvmsg | 9,756 | 776 | 13x | ### | BAD |
| write fault, page absent | 13,785 | 1,227 | 11x | ### | BAD |
| read | 5,083 | 518 | 10x | ## | BAD |
| openat | 8,172 | 994 | 8x | ## | BAD |
| mprotect | 8,672 | 1,180 | 7x | ## | BAD |
| close | 4,443 | 628 | 7x | ## | BAD |
| mmap | 6,044 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,040,611 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 380 | 722.9 us |
| write | 8,202 | 3,448 | 420.4 us |
| other | 2 | 0 | 11.7 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
