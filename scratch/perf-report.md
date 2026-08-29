# Syscall and fault cost vs the host Linux kernel

oxide: target/perf-report-e4-08-deferred-create-r2.log
boot totals: 1367606 syscalls, 6181 ms on CPU, 4519 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| munmap | 24,490 | 1,382 | 18x | #### | BAD |
| recvfrom | 12,673 | 776 | 16x | #### | BAD |
| newfstatat | 11,607 | 788 | 15x | #### | BAD |
| write fault, page absent | 13,646 | 1,227 | 11x | ### | BAD |
| recvmsg | 8,590 | 776 | 11x | ### | BAD |
| read | 5,073 | 518 | 10x | ## | BAD |
| openat | 7,819 | 994 | 8x | ## | BAD |
| mprotect | 7,885 | 1,180 | 7x | ## | BAD |
| close | 4,177 | 628 | 7x | ## | BAD |
| mmap | 5,813 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,028,368 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 297 | 565.5 us |
| write | 8,371 | 2,690 | 321.4 us |
| other | 2 | 0 | 26.8 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
