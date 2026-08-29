# Syscall and fault cost vs the host Linux kernel

oxide: target/perf-report-e4-08-mkdir-unchecked.log
boot totals: 1367508 syscalls, 6768 ms on CPU, 4949 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 19,314 | 788 | 25x | ###### | SEVERE |
| recvfrom | 15,091 | 776 | 19x | ##### | BAD |
| munmap | 23,568 | 1,382 | 17x | #### | BAD |
| recvmsg | 10,921 | 776 | 14x | ### | BAD |
| write fault, page absent | 15,841 | 1,227 | 13x | ### | BAD |
| read | 5,245 | 518 | 10x | ## | BAD |
| openat | 8,997 | 994 | 9x | ## | BAD |
| close | 4,535 | 628 | 7x | ## | BAD |
| mprotect | 8,425 | 1,180 | 7x | ## | BAD |
| mmap | 6,020 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,051,948 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 493 | 938.6 us |
| write | 8,360 | 3,387 | 405.2 us |
| other | 2 | 0 | 28.2 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
