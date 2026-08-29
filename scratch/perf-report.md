# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64.log
boot totals: 1368243 syscalls, 6485 ms on CPU, 4739 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 19,479 | 788 | 25x | ###### | SEVERE |
| recvfrom | 13,453 | 776 | 17x | #### | BAD |
| munmap | 23,780 | 1,382 | 17x | #### | BAD |
| write fault, page absent | 14,748 | 1,227 | 12x | ### | BAD |
| recvmsg | 8,451 | 776 | 11x | ### | BAD |
| read | 4,956 | 518 | 10x | ## | BAD |
| openat | 8,697 | 994 | 9x | ## | BAD |
| mprotect | 8,577 | 1,180 | 7x | ## | BAD |
| close | 4,291 | 628 | 7x | ## | BAD |
| mmap | 5,993 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,060,240 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 272 | 517.8 us |
| write | 8,071 | 3,456 | 428.3 us |
| other | 2 | 0 | 19.9 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
