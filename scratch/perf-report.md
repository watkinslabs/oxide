# Syscall and fault cost vs the host Linux kernel

oxide: target/perf-report-e4-08-dir-start-hint-r2.log
boot totals: 1367714 syscalls, 6448 ms on CPU, 4714 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| recvfrom | 13,518 | 776 | 17x | #### | BAD |
| munmap | 23,184 | 1,382 | 17x | #### | BAD |
| newfstatat | 11,393 | 788 | 14x | ### | BAD |
| recvmsg | 11,175 | 776 | 14x | ### | BAD |
| write fault, page absent | 13,678 | 1,227 | 11x | ### | BAD |
| read | 5,061 | 518 | 10x | ## | BAD |
| openat | 7,933 | 994 | 8x | ## | BAD |
| close | 4,851 | 628 | 8x | ## | BAD |
| mprotect | 8,167 | 1,180 | 7x | ## | BAD |
| mmap | 5,883 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,053,617 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 275 | 523.1 us |
| write | 8,437 | 3,189 | 378.0 us |
| other | 2 | 0 | 32.8 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
