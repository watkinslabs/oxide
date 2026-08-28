# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2812/target/perf-report-x86_64.log
boot totals: 1366340 syscalls, 6425 ms on CPU, 4702 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 20,335 | 788 | 26x | ###### | SEVERE |
| recvfrom | 13,404 | 776 | 17x | #### | BAD |
| munmap | 22,006 | 1,382 | 16x | #### | BAD |
| write fault, page absent | 14,922 | 1,227 | 12x | ### | BAD |
| recvmsg | 7,896 | 776 | 10x | ## | BAD |
| read | 4,710 | 518 | 9x | ## | BAD |
| openat | 8,493 | 994 | 9x | ## | BAD |
| mprotect | 8,293 | 1,180 | 7x | ## | BAD |
| mmap | 8,672 | 1,382 | 6x | ## | BAD |
| close | 3,590 | 628 | 6x | # | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,935,375 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 222 | 423.5 us |
| write | 8,180 | 2,448 | 299.3 us |
| flush | 31 | 196 | 6333.6 us |
| other | 2 | 0 | 11.4 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
