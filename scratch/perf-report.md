# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2673/target/perf-report-x86_64.log
boot totals: 1361854 syscalls, 11645 ms on CPU, 8550 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| writev | 1,279,808 | 495 | 2585x | ######################## | SEVERE |
| sendmmsg | 58,250 | 776 | 75x | ################## | SEVERE |
| munmap | 83,819 | 1,382 | 61x | ############### | SEVERE |
| recvmsg | 46,291 | 776 | 60x | ############## | SEVERE |
| sendmsg | 43,598 | 776 | 56x | ############# | SEVERE |
| recvfrom | 26,250 | 776 | 34x | ######## | SEVERE |
| newfstatat | 26,007 | 788 | 33x | ######## | SEVERE |
| close | 15,013 | 628 | 24x | ###### | SEVERE |
| read | 9,007 | 518 | 17x | #### | BAD |
| mprotect | 18,512 | 1,180 | 16x | #### | BAD |
| openat | 11,235 | 994 | 11x | ### | BAD |
| write fault, page absent | 11,672 | 1,227 | 10x | ## | BAD |
| mmap | 12,489 | 1,382 | 9x | ## | BAD |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 17,386 | 3,490 | 200.7 us |
| write | 409,157 | 31,074 | 75.9 us |
| flush | 2,984 | 19,049 | 6384.0 us |
| other | 2 | 0 | 32.1 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.
