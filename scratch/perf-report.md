# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64.log
boot totals: 1367140 syscalls, 6653 ms on CPU, 4866 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 19,635 | 788 | 25x | ###### | SEVERE |
| recvfrom | 15,098 | 776 | 19x | ##### | BAD |
| munmap | 23,709 | 1,382 | 17x | #### | BAD |
| recvmsg | 10,945 | 776 | 14x | ### | BAD |
| write fault, page absent | 15,893 | 1,227 | 13x | ### | BAD |
| read | 4,738 | 518 | 9x | ## | BAD |
| openat | 8,588 | 994 | 9x | ## | BAD |
| close | 4,575 | 628 | 7x | ## | BAD |
| mprotect | 8,242 | 1,180 | 7x | ## | BAD |
| mmap | 5,985 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,070,449 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 262 | 499.5 us |
| write | 8,096 | 3,075 | 379.8 us |
| other | 2 | 0 | 32.3 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
