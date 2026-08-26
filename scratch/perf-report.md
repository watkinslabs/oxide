# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2676/target/perf-report-x86_64.log
boot totals: 1363132 syscalls, 13270 ms on CPU, 9735 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| writev | 1,408,230 | 495 | 2845x | ######################## | SEVERE |
| recvmsg | 91,713 | 776 | 118x | ######################## | SEVERE |
| sendmmsg | 71,013 | 776 | 92x | ###################### | SEVERE |
| munmap | 105,380 | 1,382 | 76x | ################## | SEVERE |
| sendmsg | 54,816 | 776 | 71x | ################# | SEVERE |
| recvfrom | 27,927 | 776 | 36x | ######### | SEVERE |
| newfstatat | 27,205 | 788 | 35x | ######## | SEVERE |
| close | 19,290 | 628 | 31x | ####### | SEVERE |
| read | 9,457 | 518 | 18x | #### | BAD |
| mprotect | 18,204 | 1,180 | 15x | #### | BAD |
| openat | 11,333 | 994 | 11x | ### | BAD |
| mmap | 11,648 | 1,382 | 8x | ## | BAD |
| write fault, page absent | 9,929 | 1,227 | 8x | ## | BAD |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 16,507 | 3,378 | 204.6 us |
| write | 413,407 | 32,988 | 79.8 us |
| flush | 3,014 | 24,870 | 8251.5 us |
| other | 2 | 0 | 9.5 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
