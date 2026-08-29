# Syscall and fault cost vs the host Linux kernel

oxide: target/perf-report-e4-08-no-special-reread.log
boot totals: 1367244 syscalls, 6219 ms on CPU, 4549 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| recvfrom | 13,525 | 776 | 17x | #### | BAD |
| munmap | 23,563 | 1,382 | 17x | #### | BAD |
| newfstatat | 11,546 | 788 | 15x | #### | BAD |
| recvmsg | 10,230 | 776 | 13x | ### | BAD |
| write fault, page absent | 14,422 | 1,227 | 12x | ### | BAD |
| read | 5,010 | 518 | 10x | ## | BAD |
| openat | 7,812 | 994 | 8x | ## | BAD |
| close | 4,593 | 628 | 7x | ## | BAD |
| mprotect | 8,138 | 1,180 | 7x | ## | BAD |
| mmap | 5,850 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,049,963 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 283 | 539.0 us |
| write | 7,982 | 3,219 | 403.4 us |
| other | 2 | 0 | 28.3 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
