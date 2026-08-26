# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2677/target/perf-report-x86_64.log
boot totals: 1363580 syscalls, 8359 ms on CPU, 6130 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| writev | 1,315,092 | 495 | 2657x | ######################## | SEVERE |
| sendmmsg | 51,938 | 776 | 67x | ################ | SEVERE |
| munmap | 89,252 | 1,382 | 65x | ############### | SEVERE |
| sendmsg | 40,985 | 776 | 53x | ############# | SEVERE |
| newfstatat | 22,848 | 788 | 29x | ####### | SEVERE |
| recvfrom | 18,166 | 776 | 23x | ###### | SEVERE |
| write fault, page absent | 20,901 | 1,227 | 17x | #### | BAD |
| mprotect | 17,976 | 1,180 | 15x | #### | BAD |
| recvmsg | 10,270 | 776 | 13x | ### | BAD |
| openat | 10,782 | 994 | 11x | ### | BAD |
| read | 5,581 | 518 | 11x | ### | BAD |
| mmap | 11,852 | 1,382 | 9x | ## | BAD |
| close | 3,241 | 628 | 5x | # | BAD |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 18,703 | 8,138 | 435.1 us |
| write | 7,882 | 2,271 | 288.2 us |
| flush | 27 | 160 | 5949.6 us |
| other | 2 | 0 | 19.7 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
