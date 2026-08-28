# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-E4-05/target/perf-report-x86_64.log
boot totals: 1367540 syscalls, 6968 ms on CPU, 5095 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 20,128 | 788 | 26x | ###### | SEVERE |
| recvfrom | 15,666 | 776 | 20x | ##### | SEVERE |
| munmap | 24,327 | 1,382 | 18x | #### | BAD |
| recvmsg | 9,072 | 776 | 12x | ### | BAD |
| write fault, page absent | 14,034 | 1,227 | 11x | ### | BAD |
| read | 5,306 | 518 | 10x | ## | BAD |
| openat | 9,048 | 994 | 9x | ## | BAD |
| mprotect | 8,327 | 1,180 | 7x | ## | BAD |
| close | 4,242 | 628 | 7x | ## | BAD |
| mmap | 6,021 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,077,544 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 915 | 1740.3 us |
| write | 8,044 | 2,848 | 354.2 us |
| other | 2 | 0 | 24.5 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
