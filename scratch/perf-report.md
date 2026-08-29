# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64.log
boot totals: 1368362 syscalls, 6915 ms on CPU, 5053 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 20,005 | 788 | 25x | ###### | SEVERE |
| munmap | 24,232 | 1,382 | 18x | #### | BAD |
| recvfrom | 11,628 | 776 | 15x | #### | BAD |
| recvmsg | 8,687 | 776 | 11x | ### | BAD |
| write fault, page absent | 12,872 | 1,227 | 10x | ### | BAD |
| read | 5,176 | 518 | 10x | ## | BAD |
| openat | 9,188 | 994 | 9x | ## | BAD |
| mprotect | 8,687 | 1,180 | 7x | ## | BAD |
| close | 4,003 | 628 | 6x | ## | BAD |
| mmap | 6,220 | 1,382 | 5x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,176,833 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 299 | 569.9 us |
| write | 7,991 | 4,141 | 518.3 us |
| other | 2 | 0 | 123.4 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
