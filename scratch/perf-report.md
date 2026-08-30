# Syscall and fault cost vs the host Linux kernel

oxide: target/perf-report-x86_64-e4-dio.log
boot totals: 1368643 syscalls, 5766 ms on CPU, 4213 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| recvfrom | 13,210 | 776 | 17x | #### | BAD |
| newfstatat | 12,491 | 788 | 16x | #### | BAD |
| munmap | 21,475 | 1,382 | 16x | #### | BAD |
| write fault, page absent | 14,503 | 1,227 | 12x | ### | BAD |
| read | 4,853 | 518 | 9x | ## | BAD |
| recvmsg | 6,554 | 776 | 8x | ## | BAD |
| openat | 7,459 | 994 | 8x | ## | BAD |
| mprotect | 7,421 | 1,180 | 6x | ## | BAD |
| close | 3,369 | 628 | 5x | # | BAD |
| mmap | 5,546 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,837,552 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 283 | 538.6 us |
| write | 8,000 | 2,637 | 329.7 us |
| other | 2 | 0 | 29.9 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
