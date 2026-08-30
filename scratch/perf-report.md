# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64.log
boot totals: 1564301 syscalls, 6695 ms on CPU, 4280 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| recvfrom | 17,466 | 776 | 23x | ##### | SEVERE |
| munmap | 21,623 | 1,382 | 16x | #### | BAD |
| newfstatat | 12,121 | 788 | 15x | #### | BAD |
| recvmsg | 9,486 | 776 | 12x | ### | BAD |
| write fault, page absent | 12,494 | 1,227 | 10x | ## | BAD |
| read | 4,324 | 518 | 8x | ## | BAD |
| openat | 7,039 | 994 | 7x | ## | BAD |
| mprotect | 7,669 | 1,180 | 6x | ## | BAD |
| close | 3,613 | 628 | 6x | # | BAD |
| mmap | 5,427 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,861,911 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 238 | 453.3 us |
| write | 7,668 | 3,660 | 477.3 us |
| flush | 24 | 79 | 3330.2 us |
| other | 2 | 0 | 34.7 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
