# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2812/target/perf-report-x86_64.log
boot totals: 1172124 syscalls, 6141 ms on CPU, 5239 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 22,503 | 788 | 29x | ####### | SEVERE |
| recvfrom | 12,295 | 776 | 16x | #### | BAD |
| munmap | 21,592 | 1,382 | 16x | #### | BAD |
| recvmsg | 11,477 | 776 | 15x | #### | BAD |
| write fault, page absent | 15,170 | 1,227 | 12x | ### | BAD |
| openat | 9,111 | 994 | 9x | ## | BAD |
| read | 4,577 | 518 | 9x | ## | BAD |
| mprotect | 8,055 | 1,180 | 7x | ## | BAD |
| close | 4,019 | 628 | 6x | ## | BAD |
| mmap | 8,777 | 1,382 | 6x | ## | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,956,576 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 240 | 456.7 us |
| write | 8,401 | 2,782 | 331.2 us |
| flush | 28 | 177 | 6355.1 us |
| other | 2 | 0 | 30.7 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
