# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2812/target/perf-range-x86_64-2.log
boot totals: 1366276 syscalls, 6843 ms on CPU, 5008 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 21,105 | 788 | 27x | ###### | SEVERE |
| recvfrom | 16,203 | 776 | 21x | ##### | SEVERE |
| mprotect | 22,840 | 1,180 | 19x | ##### | BAD |
| munmap | 24,928 | 1,382 | 18x | #### | BAD |
| write fault, page absent | 14,542 | 1,227 | 12x | ### | BAD |
| openat | 9,613 | 994 | 10x | ## | BAD |
| read | 4,626 | 518 | 9x | ## | BAD |
| recvmsg | 6,766 | 776 | 9x | ## | BAD |
| mmap | 9,697 | 1,382 | 7x | ## | BAD |
| close | 3,447 | 628 | 5x | # | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,300,464 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 608 | 1156.9 us |
| write | 7,919 | 2,444 | 308.6 us |
| flush | 26 | 166 | 6399.4 us |
| other | 2 | 0 | 30.8 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
