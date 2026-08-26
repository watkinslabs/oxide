# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2675/target/perf-report-x86_64.log
boot totals: 1364946 syscalls, 11874 ms on CPU, 8699 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| writev | 1,272,120 | 495 | 2570x | ######################## | SEVERE |
| recvmsg | 67,451 | 776 | 87x | ##################### | SEVERE |
| sendmmsg | 58,288 | 776 | 75x | ################## | SEVERE |
| munmap | 88,289 | 1,382 | 64x | ############### | SEVERE |
| sendmsg | 45,446 | 776 | 59x | ############## | SEVERE |
| recvfrom | 30,929 | 776 | 40x | ########## | SEVERE |
| newfstatat | 27,063 | 788 | 34x | ######## | SEVERE |
| close | 15,179 | 628 | 24x | ###### | SEVERE |
| read | 9,163 | 518 | 18x | #### | BAD |
| mprotect | 14,954 | 1,180 | 13x | ### | BAD |
| openat | 11,732 | 994 | 12x | ### | BAD |
| write fault, page absent | 11,599 | 1,227 | 9x | ## | BAD |
| mmap | 12,500 | 1,382 | 9x | ## | BAD |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 16,532 | 3,430 | 207.5 us |
| write | 389,310 | 30,558 | 78.5 us |
| flush | 2,946 | 25,168 | 8543.1 us |
| other | 2 | 0 | 32.1 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
