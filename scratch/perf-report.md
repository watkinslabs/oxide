# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-e4-08-rcu.log
boot totals: 1367073 syscalls, 6564 ms on CPU, 4802 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 19,311 | 788 | 25x | ###### | SEVERE |
| recvfrom | 13,246 | 776 | 17x | #### | BAD |
| munmap | 23,087 | 1,382 | 17x | #### | BAD |
| recvmsg | 12,104 | 776 | 16x | #### | BAD |
| write fault, page absent | 15,636 | 1,227 | 13x | ### | BAD |
| read | 4,915 | 518 | 9x | ## | BAD |
| openat | 8,837 | 994 | 9x | ## | BAD |
| mprotect | 8,321 | 1,180 | 7x | ## | BAD |
| close | 4,290 | 628 | 7x | ## | BAD |
| mmap | 5,968 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,140,607 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 301 | 572.4 us |
| write | 8,422 | 2,942 | 349.4 us |
| other | 2 | 0 | 28.7 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
