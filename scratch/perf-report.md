# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2686/target/perf-report-x86_64.log
boot totals: 1364841 syscalls, 8482 ms on CPU, 6215 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| sendmmsg | 52,155 | 776 | 67x | ################ | SEVERE |
| munmap | 85,344 | 1,382 | 62x | ############### | SEVERE |
| sendmsg | 41,580 | 776 | 54x | ############# | SEVERE |
| newfstatat | 22,176 | 788 | 28x | ####### | SEVERE |
| recvfrom | 18,559 | 776 | 24x | ###### | SEVERE |
| write fault, page absent | 19,400 | 1,227 | 16x | #### | BAD |
| recvmsg | 12,098 | 776 | 16x | #### | BAD |
| mprotect | 17,674 | 1,180 | 15x | #### | BAD |
| read | 5,664 | 518 | 11x | ### | BAD |
| openat | 10,509 | 994 | 11x | ### | BAD |
| mmap | 12,361 | 1,382 | 9x | ## | BAD |
| close | 3,511 | 628 | 6x | # | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,325,432 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 18,556 | 7,469 | 402.5 us |
| write | 8,208 | 1,936 | 236.0 us |
| flush | 27 | 189 | 7003.2 us |
| other | 2 | 0 | 32.3 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
