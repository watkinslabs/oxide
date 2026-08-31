# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64.log
boot totals: 1368471 syscalls, 6386 ms on CPU, 4667 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| recvfrom | 15,750 | 776 | 20x | ##### | SEVERE |
| newfstatat | 12,893 | 788 | 16x | #### | BAD |
| munmap | 22,567 | 1,382 | 16x | #### | BAD |
| recvmsg | 9,798 | 776 | 13x | ### | BAD |
| write fault, page absent | 15,377 | 1,227 | 13x | ### | BAD |
| read | 4,838 | 518 | 9x | ## | BAD |
| openat | 7,687 | 994 | 8x | ## | BAD |
| mprotect | 7,969 | 1,180 | 7x | ## | BAD |
| close | 3,604 | 628 | 6x | # | BAD |
| mmap | 5,930 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,951,611 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 395 | 751.3 us |
| write | 5,715 | 2,525 | 442.0 us |
| flush | 47 | 135 | 2882.6 us |
| other | 2 | 0 | 30.1 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
